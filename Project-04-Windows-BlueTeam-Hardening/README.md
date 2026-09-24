# Windows Blue Team System Hardening & Compliance Automation

An automated PowerShell-based security auditing and remediation framework designed to evaluate Windows endpoints against major compliance standards (**CIS Controls v8, ISO 27001, and SOC 2 Type II**).

## Features
- **Diagnostic Telemetry:** Audits firewall profile statuses, drive encryption (BitLocker), guest account configurations, and browser patch levels.
- **Automated Remediation (`-Remediate`):** Enforces strict firewall inbound blocking, triggers TPM-backed BitLocker encryption, and disables unauthorized local guest accounts.
- **JSON Telemetry Reporting:** Exports structured compliance outputs with CVSS v4.0 vector scoring.

## Usage

### Run Audit Mode (Dry Run)
```powershell
.\Invoke-BlueTeamHardening.ps1 -AuditOnly -ReportPath ".\Audit_Report.json"