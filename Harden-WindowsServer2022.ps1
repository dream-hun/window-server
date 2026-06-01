#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
================================================================================
 Harden-WindowsServer2022.ps1
================================================================================
 PURPOSE
   Baseline security configuration for a Windows Server 2022 host that must:
     1. Prevent standard (non-admin) users from installing OR running their
        own applications.
     2. Allow standard users to run only software installed by an
        administrator (i.e. into Program Files / Windows).
     3. Allow remote logon from anywhere over a hardened RDP channel.

 STRATEGY
   - AppLocker in *whitelist* mode. Standard users may run binaries only from
     locations they cannot write to (Program Files, Windows). Admin-installed
     software lives there, so it keeps working; anything dropped into a user
     profile, Downloads, Temp, or a USB stick is blocked.
   - Windows Installer locked down (no elevated user installs, no per-user MSI).
   - UAC configured so standard users cannot elevate at all.
   - RDP enabled with NLA + TLS + high encryption, behind account-lockout and
     strong password policy.
   - General attack-surface reduction: firewall on, SMBv1 off, legacy auth off,
     Defender on, auditing on.

 IMPORTANT - READ BEFORE RUNNING
   * Run from an *elevated* PowerShell session, ideally from the console (not an
     RDP session you could lock yourself out of). Test on a snapshot/VM first.
   * AppLocker enforcement is applied to a clean default ruleset. If you run
     line-of-business apps from non-standard paths (e.g. C:\Apps, D:\Tools),
     add publisher/path rules for them BEFORE enabling enforcement, or users
     won't be able to launch them.
   * Opening RDP to "anywhere" is inherently risky. Prefer restricting
     -RdpSourceAddresses to a VPN/office range. The "Any" default is provided
     only because it was requested.

 USAGE
   .\Harden-WindowsServer2022.ps1 `
       -RdpAllowedUsers 'CONTOSO\jdoe','CONTOSO\RemoteStaff' `
       -RdpSourceAddresses 'Any'

 Author: Senior Systems Administrator
================================================================================
#>

[CmdletBinding()]
param(
    # Users / groups to grant Remote Desktop access (added to 'Remote Desktop Users').
    [string[]] $RdpAllowedUsers = @(),

    # Source IPs/subnets allowed to reach RDP. 'Any' = open to the internet (NOT recommended).
    # Example: '203.0.113.0/24','198.51.100.10'
    [string[]] $RdpSourceAddresses = @('Any'),

    # Keep RDP on the default port unless you have a reason to change it.
    [int] $RdpPort = 3389,

    # Where to write the run transcript.
    [string] $LogPath = "C:\Hardening\Harden-Server2022_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    # Skip the AppLocker section (e.g. if you manage it via GPO instead).
    [switch] $SkipAppLocker
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section { param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}
function Write-Ok    { param([string]$m) Write-Host "  [ OK ]  $m" -ForegroundColor Green }
function Write-Info  { param([string]$m) Write-Host "  [INFO]  $m" -ForegroundColor Gray }
function Write-Warn2 { param([string]$m) Write-Host "  [WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param([string]$m) Write-Host "  [FAIL]  $m" -ForegroundColor Red }

function Set-Reg {
    param([string]$Path,[string]$Name,$Value,[string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

$Summary = [System.Collections.Generic.List[string]]::new()
function Track { param([string]$Stage,[bool]$Success,[string]$Detail='')
    $status = if ($Success) { 'SUCCESS' } else { 'FAILED ' }
    $Summary.Add(("{0} - {1} {2}" -f $status,$Stage,$Detail))
}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
Start-Transcript -Path $LogPath -Force | Out-Null

Write-Section "Windows Server 2022 Hardening"
Write-Info "Host        : $env:COMPUTERNAME"
Write-Info "OS          : $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Info "Run by      : $env:USERDOMAIN\$env:USERNAME"
Write-Info "Transcript  : $LogPath"
Write-Warn2 "Run this from the local console, not the RDP session you depend on."

# ===========================================================================
# 1. APPLOCKER  -  Application whitelisting
#    Default rules: users may run from Program Files + Windows only.
#    Admins may run anything. This is what stops users installing/running
#    their own software while keeping admin-installed apps usable.
# ===========================================================================
if (-not $SkipAppLocker) {
    Write-Section "1. AppLocker application whitelisting"
    try {
        # AppLocker needs the Application Identity service running.
        Set-Service -Name AppIDSvc -StartupType Automatic
        Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        Write-Ok "Application Identity service (AppIDSvc) set to Automatic and started."

        # SIDs: S-1-1-0 = Everyone, S-1-5-32-544 = BUILTIN\Administrators
        $appLockerXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default) All files in Program Files" Description="Allows members of the Everyone group to run applications in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default) All files in Windows" Description="Allows members of the Everyone group to run applications in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default) All files (Administrators)" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default) Digitally signed Windows Installer files" Description="Allows members of the Everyone group to run digitally signed Windows Installer files." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions>
    </FilePathRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default) Installers in %systemdrive%\Windows\Installer" Description="Allows members of the Everyone group to run Windows Installer files in the default location." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="(Default) All Windows Installer files (Administrators)" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*.*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default) Scripts in Program Files" Description="Allows members of the Everyone group to run scripts in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default) Scripts in Windows" Description="Allows members of the Everyone group to run scripts in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default) All scripts (Administrators)" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
'@
        $xmlFile = "$env:TEMP\AppLocker_Baseline.xml"
        $appLockerXml | Out-File -FilePath $xmlFile -Encoding ASCII -Force
        Set-AppLockerPolicy -XmlPolicy $xmlFile -ErrorAction Stop
        Remove-Item $xmlFile -Force -ErrorAction SilentlyContinue

        Write-Ok "AppLocker enforced: Exe, Msi, Script, Appx (whitelist baseline)."
        Write-Info "Users can run apps only from Program Files & Windows; admins unrestricted."
        Write-Warn2 "Add custom rules for any LOB apps installed outside Program Files."
        Track "AppLocker whitelisting" $true
    }
    catch { Write-Err $_.Exception.Message; Track "AppLocker whitelisting" $false $_.Exception.Message }
}
else { Write-Section "1. AppLocker (SKIPPED by parameter)" }

# ===========================================================================
# 2. BLOCK SOFTWARE INSTALLATION  -  Windows Installer + UAC
# ===========================================================================
Write-Section "2. Block software installation by standard users"
try {
    # Never allow elevated MSI installs initiated by a standard user.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0
    Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0
    # Block per-user (non-admin) Windows Installer installs.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'DisableUserInstalls' 1
    Write-Ok "Windows Installer: elevated user installs and per-user installs disabled."

    # UAC: enabled, admins prompt for consent, standard users CANNOT elevate.
    $uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-Reg $uac 'EnableLUA' 1
    Set-Reg $uac 'ConsentPromptBehaviorAdmin' 2   # prompt for consent on secure desktop
    Set-Reg $uac 'ConsentPromptBehaviorUser' 0    # auto-deny elevation for standard users
    Set-Reg $uac 'PromptOnSecureDesktop' 1
    Set-Reg $uac 'EnableInstallerDetection' 1     # detect installer exes and require elevation
    Write-Ok "UAC enforced; standard users cannot elevate (elevation auto-denied)."

    Track "Block software installation" $true
}
catch { Write-Err $_.Exception.Message; Track "Block software installation" $false $_.Exception.Message }

# ===========================================================================
# 3. REMOTE DESKTOP  -  Enable + harden
# ===========================================================================
Write-Section "3. Remote Desktop (RDP) - enable and harden"
try {
    $ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    Set-Reg $ts  'fDenyTSConnections' 0          # enable RDP
    Set-Reg $tcp 'UserAuthentication' 1          # require Network Level Authentication
    Set-Reg $tcp 'SecurityLayer' 2               # TLS 1.x
    Set-Reg $tcp 'MinEncryptionLevel' 3          # High (128-bit)
    Set-Reg $tcp 'fDisableEncryption' 0
    Write-Ok "RDP enabled with NLA + TLS + High encryption."

    if ($RdpPort -ne 3389) {
        Set-Reg $tcp 'PortNumber' $RdpPort
        Write-Ok "RDP listening port set to $RdpPort."
    }

    # Idle/session limits so abandoned sessions don't linger (15 min idle, disconnect).
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-Reg $tsPol 'MaxIdleTime'         900000   # 15 minutes
    Set-Reg $tsPol 'MaxDisconnectionTime' 3600000 # 60 minutes then logoff
    Set-Reg $tsPol 'fResetBroken' 1
    Write-Ok "RDP idle (15m) and disconnected (60m) session limits applied."

    # Firewall rule for RDP, scoped to allowed sources.
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    if ($RdpSourceAddresses -notcontains 'Any') {
        Get-NetFirewallRule -DisplayGroup "Remote Desktop" |
            Set-NetFirewallRule -RemoteAddress $RdpSourceAddresses
        Write-Ok "RDP firewall restricted to: $($RdpSourceAddresses -join ', ')"
    } else {
        Write-Warn2 "RDP firewall left open to ANY source. Restrict to a VPN/office range when possible."
    }
    if ($RdpPort -ne 3389) {
        New-NetFirewallRule -DisplayName "Custom RDP $RdpPort" -Direction Inbound `
            -Protocol TCP -LocalPort $RdpPort -Action Allow `
            -RemoteAddress $RdpSourceAddresses -ErrorAction SilentlyContinue | Out-Null
    }

    # Grant remote access only to explicitly listed accounts.
    foreach ($u in $RdpAllowedUsers) {
        try {
            Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $u -ErrorAction Stop
            Write-Ok "Added '$u' to Remote Desktop Users."
        } catch { Write-Warn2 "Could not add '$u': $($_.Exception.Message)" }
    }
    if (-not $RdpAllowedUsers) {
        Write-Warn2 "No -RdpAllowedUsers supplied. Add accounts to 'Remote Desktop Users' manually."
    }

    Track "RDP enable + harden" $true
}
catch { Write-Err $_.Exception.Message; Track "RDP enable + harden" $false $_.Exception.Message }

# ===========================================================================
# 4. ACCOUNT, PASSWORD & LOCKOUT POLICY  (local accounts)
# ===========================================================================
Write-Section "4. Account, password and lockout policy"
try {
    # Lockout: 5 bad attempts -> 15 min lock, counter resets after 15 min.
    cmd /c "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15" | Out-Null
    # Passwords: min length 14, max age 60d, min age 1d, remember 24.
    cmd /c "net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24" | Out-Null
    Write-Ok "Lockout (5/15/15) and password policy (len 14, 60d) applied to local accounts."

    # Enforce complexity + disable reversible encryption via secedit.
    $inf = "$env:TEMP\secpol.inf"; $sdb = "$env:TEMP\secpol.sdb"
    secedit /export /cfg $inf /quiet
    (Get-Content $inf) `
        -replace 'PasswordComplexity = \d', 'PasswordComplexity = 1' `
        -replace 'ClearTextPassword = \d', 'ClearTextPassword = 0' |
        Set-Content $inf
    secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet
    Remove-Item $inf,$sdb -Force -ErrorAction SilentlyContinue
    Write-Ok "Password complexity enforced; reversible encryption disabled."

    Track "Account/password/lockout policy" $true
}
catch { Write-Err $_.Exception.Message; Track "Account/password/lockout policy" $false $_.Exception.Message }

# ===========================================================================
# 5. FIREWALL
# ===========================================================================
Write-Section "5. Windows Firewall"
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -NotifyOnListen True -LogBlocked True `
        -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384
    Write-Ok "Firewall ON for all profiles; inbound blocked by default; block logging on."
    Track "Firewall" $true
}
catch { Write-Err $_.Exception.Message; Track "Firewall" $false $_.Exception.Message }

# ===========================================================================
# 6. MICROSOFT DEFENDER ANTIVIRUS
# ===========================================================================
Write-Section "6. Microsoft Defender Antivirus"
try {
    Set-MpPreference -DisableRealtimeMonitoring $false `
                     -PUAProtection Enabled `
                     -MAPSReporting Advanced `
                     -SubmitSamplesConsent SendSafeSamples `
                     -DisableScriptScanning $false `
                     -DisableArchiveScanning $false `
                     -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue

    # A couple of high-value Attack Surface Reduction rules (Block mode).
    # Block credential stealing from LSASS:
    Add-MpPreference -AttackSurfaceReductionRules_Ids '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    # Block Office child processes:
    Add-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    Write-Ok "Defender real-time, PUA, cloud, network protection and key ASR rules enabled."
    Track "Defender AV" $true
}
catch { Write-Warn2 "Defender step partially applied: $($_.Exception.Message)"; Track "Defender AV" $false $_.Exception.Message }

# ===========================================================================
# 7. LEGACY PROTOCOL / SURFACE REDUCTION
# ===========================================================================
Write-Section "7. Disable legacy protocols and reduce attack surface"
try {
    # SMBv1 off (server + client).
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "SMBv1 disabled."

    # Require SMB signing.
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
    Write-Ok "SMB signing required."

    # LAN Manager / NTLMv1 off: NTLMv2 only, no LM hash storage.
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-Reg $lsa 'LmCompatibilityLevel' 5   # send NTLMv2 only, refuse LM & NTLM
    Set-Reg $lsa 'NoLMHash' 1
    Set-Reg $lsa 'RestrictAnonymous' 1
    Set-Reg $lsa 'RestrictAnonymousSAM' 1
    Write-Ok "LM/NTLMv1 disabled (NTLMv2 only); anonymous enumeration restricted."

    # Disable AutoRun/AutoPlay (USB/removable malware vector).
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
    Write-Ok "AutoRun / AutoPlay disabled."

    Track "Legacy protocol reduction" $true
}
catch { Write-Err $_.Exception.Message; Track "Legacy protocol reduction" $false $_.Exception.Message }

# ===========================================================================
# 8. AUDIT / LOGGING
# ===========================================================================
Write-Section "8. Audit policy"
try {
    auditpol /set /category:"Logon/Logoff"      /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Logon"     /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Policy Change"     /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Privilege Use"     /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    # Include the command line in process-creation events (forensics gold).
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Write-Ok "Auditing enabled for logon, account, policy, privilege use, and process creation."
    Track "Audit policy" $true
}
catch { Write-Err $_.Exception.Message; Track "Audit policy" $false $_.Exception.Message }

# ===========================================================================
# 9. REPORT: who is a local administrator (review for least privilege)
# ===========================================================================
Write-Section "9. Local administrators review"
try {
    $admins = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name
    Write-Info "Members of local Administrators group:"
    $admins | ForEach-Object { Write-Host "         - $_" -ForegroundColor Yellow }
    Write-Warn2 "Anyone here bypasses AppLocker and install restrictions. Keep this list minimal."
}
catch { Write-Warn2 "Could not enumerate Administrators: $($_.Exception.Message)" }

# ===========================================================================
# SUMMARY
# ===========================================================================
Write-Section "Summary"
$Summary | ForEach-Object {
    if ($_ -like 'SUCCESS*') { Write-Host "  $_" -ForegroundColor Green }
    else                     { Write-Host "  $_" -ForegroundColor Red }
}
Write-Host ""
Write-Warn2 "Reboot recommended so all policies (UAC, SMB, AppLocker) fully take effect."
Write-Info "Full transcript saved to: $LogPath"
Write-Info "Verify AppLocker:  Get-AppLockerPolicy -Effective -Xml"
Write-Info "Test enforcement:  log in as a standard user and try to run an EXE from Downloads."

Stop-Transcript | Out-Null
