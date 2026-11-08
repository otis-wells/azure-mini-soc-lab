
# Data Collection and Log Ingestion

## Overview

Effective security monitoring relies on collecting relevant endpoint telemetry and making it available for analysis.

Within this project, Azure Monitor Agent (AMA), Data Collection Rules (DCRs), Windows Security Events, Sysmon and PowerShell logging were used to establish endpoint visibility.

## Azure Monitor Agent (AMA)

Azure Monitor Agent was deployed on the Windows virtual machine `soc-win01`.

AMA collects configured event data and forwards it to the designated Log Analytics workspace according to the associated Data Collection Rules.

## Data Collection Rules (DCR)

Data Collection Rules were configured to define the security events collected from the monitored endpoint.

The Windows Security Events collection configuration included:

- Audit Success events.
- Audit Failure events.

These events provide visibility into authentication activity and other security-relevant Windows events.

## Additional Telemetry Sources

### Windows Security Events

Windows Security Event Logs provide information about authentication and system security activity.

Event ID 4625 was particularly relevant to the lab, providing visibility into failed logon attempts.

### PowerShell Operational Logging

PowerShell Script Block Logging was enabled to capture executed PowerShell script content.

Event ID 4104 was used to support the monitoring and investigation of PowerShell activity.

### Sysmon

Sysmon was deployed to provide additional endpoint telemetry, improving visibility into system activity and supporting security investigations.

## Log Ingestion and Validation

Following the configuration of AMA and the associated DCRs, collected events were validated within the Log Analytics workspace.

The `SecurityEvent` table was used to confirm the ingestion of Windows Security Events.

Event data was queried using Kusto Query Language (KQL) to validate collection and support subsequent detection development.

## Outcome

The data collection configuration established the telemetry foundation required for the SOC lab.

Successful event ingestion enabled the development, testing and validation of custom detection rules within Microsoft Sentinel.

