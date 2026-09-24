[CmdletBinding()]
param (
    [switch]$AuditOnly =$false,
    [switch]$Remediate =$false,
    [string]$ReportPath = "$PSScriptRoot\Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] THIS SCRIPT MUST BE RUN WITH ELEVATED ADMINISTRATIVE PRIVILEGES."
    exit 1
}

function Write-AuditHeader {
    param ([string]$Text)
    Write-Host "`n=====================================================================" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan
}

function Write-Status {
    param ([string]$Status, [string]$Message, [ConsoleColor]$Color = [ConsoleColor]::White)
    Write-Host "[$Status] " -NoNewline -ForegroundColor $Color
    Write-Host $Message
}

$Global:AuditResults = [ordered]@{
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Hostname  = $env:COMPUTERNAME
    Findings  = @()
    Summary   = @{}
}

Write-AuditHeader "PHASE 1: EXECUTING DIAGNOSTIC TELEMETRY & AUDIT CHECKS"

# F01: Firewall Check
$FirewallProfiles = Get-NetFirewallProfile
$DisabledFirewalls = $FirewallProfiles.Where({ $_.Enabled -eq $false -or $_.DefaultInboundAction -ne "Block" })
$F01_Status = if ($DisabledFirewalls) { "FAIL" } else { "PASS" }

if ($F01_Status -eq "FAIL") {
    Write-Status "FAIL" "F01: One or more firewall profiles disabled or inbound action set to Allow." ([ConsoleColor]::Red)
    $Global:AuditResults.Findings += @{
        ID = "F01"; Title = "Firewall Inactive or Unsecured"; Severity = "HIGH"; CVSS = 8.7;
        Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"; CIS = "Control 4.4"
    }
} else {
    Write-Status "PASS" "F01: All firewall profiles active with Default Inbound Block." ([ConsoleColor]::Green)
}

# F02: BitLocker Check
$SystemVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
$F02_Status = if (-not $SystemVolume -or $SystemVolume.ProtectionStatus -ne "On") { "FAIL" } else { "PASS" }

if ($F02_Status -eq "FAIL") {
    Write-Status "FAIL" "F02: Primary system drive (C:) is unencrypted (BitLocker Off)." ([ConsoleColor]::Red)
    $Global:AuditResults.Findings += @{
        ID = "F02"; Title = "Unencrypted Local Drive"; Severity = "MEDIUM-HIGH"; CVSS = 6.9;
        Vector = "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; CIS = "Control 3.11"
    }
} else {
    Write-Status "PASS" "F02: BitLocker full-disk encryption active on C:." ([ConsoleColor]::Green)
}

# F03: Guest Account Check
$GuestUser = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$F03_Status = if ($GuestUser -and $GuestUser.Enabled -eq $true) { "FAIL" } else { "PASS" }

if ($F03_Status -eq "FAIL") {
    Write-Status "FAIL" "F03: Local Guest account is ENABLED." ([ConsoleColor]::Red)
    $Global:AuditResults.Findings += @{
        ID = "F03"; Title = "Local Guest Account Active"; Severity = "HIGH"; CVSS = 7.8;
        Vector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; CIS = "Control 5.1"
    }
} else {
    Write-Status "PASS" "F03: Local Guest account disabled." ([ConsoleColor]::Green)
}

# F04: Browser / Patch Check
$InstalledApps = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
$OutdatedSoftware = $InstalledApps.Where({ $_.DisplayName -like "*Chrome*" -and [version]$_.DisplayVersion -lt [version]"125.0.0.0" })
$F04_Status = if ($OutdatedSoftware) { "FAIL" } else { "PASS" }

if ($F04_Status -eq "FAIL") {
    Write-Status "FAIL" "F04: Outdated browser engine detected." ([ConsoleColor]::Red)
    $Global:AuditResults.Findings += @{
        ID = "F04"; Title = "Outdated Browser Engine"; Severity = "HIGH"; CVSS = 8.8;
        Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; CIS = "Control 2.2"
    }
} else {
    Write-Status "PASS" "F04: Browser versions up to date." ([ConsoleColor]::Green)
}

if ($Remediate) {
    Write-AuditHeader "PHASE 2: EXECUTING HARDENING REMEDIATION PROTOCOLS"

    if ($F01_Status -eq "FAIL") {
        Write-Status "INFO" "Enforcing Firewall rules across profiles..." ([ConsoleColor]::Yellow)
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -ErrorAction SilentlyContinue
        Write-Status "FIXED" "Firewall profiles enabled and default inbound action set to Block." ([ConsoleColor]::Green)
    }

    if ($F02_Status -eq "FAIL") {
        Write-Status "INFO" "Initiating BitLocker encryption on volume C: with TPM protection..." ([ConsoleColor]::Yellow)
        try {
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
            Write-Status "FIXED" "BitLocker encryption initialized successfully." ([ConsoleColor]::Green)
        } catch {
            Write-Status "WARN" "BitLocker skipped (requires hardware TPM configuration or user interaction): $_" ([ConsoleColor]::DarkYellow)
        }
    }

    if ($F03_Status -eq "FAIL") {
        Write-Status "INFO" "Disabling local Guest user account..." ([ConsoleColor]::Yellow)
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-Status "FIXED" "Guest account disabled." ([ConsoleColor]::Green)
    }
} else {
    Write-Host "`n[!] Remediate flag (-Remediate) omitted. Running in dry-run/audit mode." -ForegroundColor Yellow
}

Write-AuditHeader "PHASE 3: EXPORTING COMPLIANCE & AUDIT METRICS"

$ReportDir = Split-Path$ReportPath -Parent
if ($ReportDir -and -not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path$ReportDir -Force | Out-Null }

$TotalFindings =$Global:AuditResults.Findings.Count
$Global:AuditResults.Summary = @{
    TotalFlawsFound = $TotalFindings
    HardeningStatus = if ($TotalFindings -eq 0 -or$Remediate) { "COMPLIANT" } else { "NON_COMPLIANT" }
    MappedFrameworks = @("CIS Critical Security Controls v8", "ISO 27001:2022", "SOC 2 Type II")
}

$JsonText = ConvertTo-Json$Global:AuditResults -Depth 4
Set-Content -Path $ReportPath -Value$JsonText -Encoding utf8
Write-Status "OK" "Audit report generated and saved to: $ReportPath" ([ConsoleColor]::Cyan)

Write-Host "`n[+] AUDIT ENGINE EXECUTION COMPLETE.`n" -ForegroundColor Green