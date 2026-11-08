
# Detection 03 – PowerShell Script Block Logging

## Overview

This detection monitors PowerShell script block execution using Windows PowerShell Operational Event ID 4104.

Script Block Logging records the contents of PowerShell script blocks as they are processed by the PowerShell engine. This provides visibility into commands and scripts executed on the endpoint, helping analysts investigate potentially suspicious PowerShell activity.

The query extracts the script block contents and associated file path from Event ID 4104 records, providing visibility into PowerShell execution activity on the monitored Windows endpoint.

## Detection Configuration

| Configuration | Value |
|---|---|
| Detection Name | PowerShell Script Block Logging |
| Data Source | PowerShell Operational Logs |
| Event ID | 4104 |
| Severity | Low |
| MITRE ATT&CK Tactic | Execution |
| MITRE ATT&CK Technique | T1059.001 – PowerShell |
| Monitored Endpoint | `soc-win01` |

## Detection Logic

The query retrieves PowerShell script block logging events and extracts relevant execution information.

The detection performs the following operations:

1. **Identify PowerShell activity:** Filters the Event table for Event ID 4104.
2. **Extract script contents:** Retrieves the `ScriptBlockText` field containing the recorded PowerShell script or command.
3. **Extract execution path:** Retrieves the `Path` field to identify the associated script file location, where available.
4. **Filter incomplete records:** Excludes events where script block contents are empty.
5. **Select relevant information:** Returns the event timestamp, computer name, username, script block contents and associated path.
6. **Sort results:** Orders events by timestamp, displaying the most recent PowerShell activity first.

## KQL Detection Query

```kql
Event
| where EventID == 4104
| extend
    ScriptBlockText = extract(@"<Data Name=""ScriptBlockText"">(.*?)</Data>", 1, EventData),
    Path = extract(@"<Data Name=""Path"">(.*?)</Data>", 1, EventData)
| where isnotempty(ScriptBlockText)
| project
    TimeGenerated,
    Computer,
    UserName,
    ScriptBlockText,
    Path
| order by TimeGenerated desc
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---|---|---|
| Execution | PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |

This detection maps to MITRE ATT&CK technique T1059.001 because it provides visibility into PowerShell execution, a command and scripting interpreter that can be used by both legitimate administrators and threat actors.

## Testing and Validation

The detection was tested within the Azure Mini-SOC environment using intentionally simulated PowerShell activity.

Validation included:

- Executing PowerShell commands on the Windows lab endpoint.
- Confirming that PowerShell Script Block Logging was enabled.
- Generating Event ID 4104 records.
- Confirming that the events were ingested into the Log Analytics Workspace.
- Verifying that the query extracted script block contents and associated paths.
- Reviewing the returned timestamps, computer names and user information.

**Lab Validation:** All activity was intentionally simulated within the isolated lab environment.

## Recommended Response

If suspicious PowerShell activity is identified, an analyst should:

1. Review the recorded script block contents to understand what commands were executed.
2. Identify the associated user account and endpoint.
3. Investigate the script path and determine whether the file is legitimate.
4. Look for suspicious commands, encoded content, download activity or attempts to execute external scripts.
5. Correlate the activity with other security events, including process creation and network connections.
6. Determine whether the activity is authorised administrative work or potentially malicious execution.
7. If malicious activity is suspected, follow the organisation's incident response procedures.

## Outcome

Successfully demonstrated the collection and extraction of PowerShell Script Block Logging events from the Windows lab endpoint.

The detection provides visibility into PowerShell execution activity and establishes a foundation for more targeted detections identifying suspicious or potentially malicious PowerShell commands.
