
# Detection Engineering

## Overview

Detection engineering was a core component of the Azure Mini-SOC project.

Six custom detection scenarios were developed using Kusto Query Language (KQL) to identify potentially suspicious activity within the monitored Windows environment.

The detection rules were designed to identify authentication anomalies, suspicious PowerShell execution and potentially malicious Windows service creation.

## Detection Development

Custom KQL queries were developed and configured as Microsoft Sentinel analytics rules.

Each detection was designed around specific Windows event data, with appropriate thresholds and conditions to identify suspicious behaviour.

## Detection Scenarios

| Detection | Event ID | MITRE ATT&CK |
|---|---:|---|
| Multiple failed logon attempts | 4625 | T1110 |
| Failed logon followed by successful authentication | 4625 / 4624 | T1110 |
| PowerShell script block logging | 4104 | T1059.001 |
| Suspicious PowerShell execution | 4104 | T1059.001 |
| Windows service creation | 7045 | T1543.003 |
| Suspicious service creation | 7045 | T1543.003 |

## Authentication Monitoring

Windows Security Events were used to monitor authentication activity.

Event ID 4625 was used to identify failed logon attempts, while Event ID 4624 provided visibility into successful authentication.

Detection logic was developed to identify repeated authentication failures and investigate instances where failed authentication was followed by a successful logon.

## PowerShell Monitoring

PowerShell activity was monitored using Script Block Logging.

Event ID 4104 provided visibility into executed PowerShell script blocks.

Custom detection logic was developed to identify potentially suspicious execution patterns, including encoded commands, Base64 decoding, download activity and suspicious command execution.

## Windows Service Monitoring

Windows Event ID 7045 was used to monitor the installation of new Windows services.

Additional detection logic was developed to identify potentially suspicious service creation based on service paths, execution locations and associated command patterns.

## Testing and Validation

Detection rules were validated through intentionally simulated activity within the lab environment.

Testing included:

- Generating repeated failed authentication attempts.
- Simulating failed authentication followed by successful logon.
- Executing PowerShell commands.
- Generating suspicious PowerShell execution patterns.
- Creating Windows services.
- Simulating suspicious service creation.

Generated events were reviewed within Log Analytics and Microsoft Sentinel to confirm that the detection logic operated as intended.

## MITRE ATT&CK Mapping

Detection scenarios were mapped to relevant MITRE ATT&CK techniques to provide a structured approach to classifying the activity being monitored.

- **T1110 – Brute Force**
- **T1059.001 – PowerShell**
- **T1543.003 – Windows Service**

## Outcome

Six detection scenarios were successfully developed, tested and validated.

The completed detection capabilities demonstrate practical experience in KQL development, security event analysis, threat detection and SIEM alert configuration.

