
# Detection 05 – Windows Service Creation

## Overview

This detection monitors the creation of new Windows services using Windows System Event ID 7045.

Windows services are commonly used by legitimate applications and system components to run background processes. However, threat actors can also abuse service creation to establish persistence, execute malicious programs or maintain access to compromised systems.

The detection identifies newly installed services and extracts relevant information, including the service name, executable path, service type, start configuration and associated account.

This provides analysts with visibility into service creation activity and supports the investigation of potentially unauthorised or suspicious installations.

## Detection Configuration

| Configuration | Value |
|---|---|
| Detection Name | Windows Service Creation |
| Data Source | Windows System Logs |
| Event ID | 7045 |
| Severity | Low |
| MITRE ATT&CK Tactic | Persistence |
| MITRE ATT&CK Technique | [T1543.003 – Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| Lookback Period | 5 minutes |
| Monitored Endpoint | `soc-win01` |

## Detection Logic

The query retrieves Windows service creation events and extracts relevant service configuration details.

The detection performs the following operations:

1. **Identify service creation events:** Filters the Event table for Event ID 7045.
2. **Apply the time window:** Restricts results to events generated within the previous five minutes.
3. **Extract service information:** Retrieves the service name and executable image path.
4. **Identify service configuration:** Extracts the service type and configured start type.
5. **Identify the service account:** Retrieves the account associated with the service.
6. **Present investigation details:** Returns the event timestamp, endpoint and extracted service information for further investigation.

## KQL Detection Query

```kql id="f7xq2c"
Event
| where TimeGenerated > ago(5m)
| where EventID == 7045
| extend
    ServiceName = extract(@"<Data Name=""ServiceName"">(.*?)</Data>", 1, EventData),
    ImagePath = extract(@"<Data Name=""ImagePath"">(.*?)</Data>", 1, EventData),
    ServiceType = extract(@"<Data Name=""ServiceType"">(.*?)</Data>", 1, EventData),
    StartType = extract(@"<Data Name=""StartType"">(.*?)</Data>", 1, EventData),
    AccountName = extract(@"<Data Name=""AccountName"">(.*?)</Data>", 1, EventData)
| project
    TimeGenerated,
    Computer,
    ServiceName,
    ImagePath,
    ServiceType,
    StartType,
    AccountName
```

## MITRE ATT&CK Mapping

| Category | Mapping |
|---|---|
| Tactic | Persistence |
| Technique | [T1543.003 – Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

This detection maps to MITRE ATT&CK technique T1543.003 because threat actors can create or modify Windows services to establish persistence and execute malicious code.

## Testing and Validation

The detection was tested within the Azure Mini-SOC environment using intentionally simulated service creation activity.

Validation included:

- Creating a Windows service on the lab endpoint.
- Confirming that Windows Event ID 7045 was generated.
- Verifying that the event was ingested into the Log Analytics Workspace.
- Confirming that the query identified the service creation event.
- Reviewing the extracted service name, executable path, service type, start type and associated account.

**Lab Validation:** All activity was intentionally simulated within the isolated lab environment.

## Recommended Response

If this detection triggers in a production environment, an analyst should:

1. Identify the newly created service and the affected endpoint.
2. Review the service name and executable image path.
3. Determine whether the executable is legitimate and located in an expected directory.
4. Review the service account and configured start type.
5. Establish whether the service creation was associated with an authorised software installation or administrative activity.
6. Investigate the executable and its associated processes for suspicious behaviour.
7. Correlate the event with other security telemetry to identify potential persistence or malicious activity.
8. If the service is suspected to be malicious, follow the organisation's incident response procedures.

## Outcome

Successfully demonstrated the collection and identification of Windows service creation events using Event ID 7045.

The detection provides visibility into newly installed services and captures important configuration details to support security investigations.

It also establishes a foundation for more targeted service creation detections, particularly those identifying suspicious executable paths, unusual service accounts or potentially malicious execution methods.
