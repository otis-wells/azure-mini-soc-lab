
# Detection 06 – Suspicious Windows Service Creation

## Overview

This detection identifies potentially suspicious Windows service creation events using Windows Event ID **7045**.

Unlike the general service creation detection, this rule examines the service executable path (`ImagePath`) for indicators that may suggest malicious activity.

Suspicious indicators include:
- Executables launched from user-writable or temporary directories.
- PowerShell or other command interpreters configured as service executables.
- Script hosts such as `wscript.exe`, `cscript.exe` and `mshta.exe`.
- Encoded command indicators within the executable path.

These behaviours may indicate an attempt to establish persistence or execute malicious code through a Windows service.

## Detection Configuration

| Setting | Value |
|---|---|
| Data Source | Windows System Logs |
| Event ID | 7045 |
| Detection Type | Suspicious Service Creation |
| Severity | To be confirmed |
| MITRE Tactic | Persistence |
| MITRE Technique | T1543.003 – Windows Service |
| Lookback Period | 30 minutes |
| Endpoint | `soc-win01` |

## Detection Logic

The query performs the following operations:

1. Filters for Windows Event ID 7045 within the previous 30 minutes.
2. Extracts service details, including service name, executable path, service type, start type and account name.
3. Converts the executable path to lowercase to support consistent matching.
4. Searches for suspicious directory paths, including user profiles, AppData, Temp, Public and Downloads.
5. Identifies potentially suspicious executables, including PowerShell, command prompt and script-hosting utilities.
6. Checks for encoded command indicators.
7. Assigns a detection reason to explain which suspicious condition triggered the rule.
8. Returns the relevant service information for investigation.

## KQL Query

```kql
Event
| where TimeGenerated > ago(30m)
| where EventID == 7045
| extend
    ServiceName = extract(@"<Data Name=""ServiceName"">(.*?)</Data>", 1, EventData),
    ImagePath = extract(@"<Data Name=""ImagePath"">(.*?)</Data>", 1, EventData),
    ServiceType = extract(@"<Data Name=""ServiceType"">(.*?)</Data>", 1, EventData),
    StartType = extract(@"<Data Name=""StartType"">(.*?)</Data>", 1, EventData),
    AccountName = extract(@"<Data Name=""AccountName"">(.*?)</Data>", 1, EventData)
| extend NormalizedPath = tolower(ImagePath)
| where
    NormalizedPath has_any (
        @"\users\",
        @"\appdata\",
        @"\temp\",
        @"\public\",
        @"\downloads\"
    )
    or NormalizedPath has_any (
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe"
    )
    or NormalizedPath contains "-enc"
    or NormalizedPath contains "encodedcommand"
| extend DetectionReason = case(
    NormalizedPath has_any (@"\users\", @"\appdata\", @"\temp\", @"\public\", @"\downloads\"),
        "Service executable located in user-writable or temporary path",
    NormalizedPath has_any ("powershell.exe", "pwsh.exe"),
        "PowerShell used as service executable",
    NormalizedPath has_any ("cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"),
        "Command interpreter or script host used as service executable",
    NormalizedPath contains "-enc" or NormalizedPath contains "encodedcommand",
        "Encoded command detected in service executable",
    "Suspicious service executable"
)
| project
    TimeGenerated,
    Computer,
    ServiceName,
    ImagePath,
    ServiceType,
    StartType,
    AccountName,
    DetectionReason
```

## MITRE ATT&CK Mapping

| Category | Mapping |
|---|---|
| Tactic | Persistence |
| Technique | [T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |

## Testing and Validation

The detection was tested using intentionally simulated service creation activity within the lab environment.

Validation included:

- Generating Windows service creation events on `soc-win01`.
- Confirming Event ID 7045 was successfully ingested.
- Verifying that service details were extracted correctly.
- Checking that suspicious executable paths and process names were identified.
- Confirming that the `DetectionReason` field described the matching indicator.

All activity was intentionally simulated within the lab environment.

## Recommended Response

If this detection triggers:

1. **Identify the service:** Review the service name, executable path and associated endpoint.
2. **Inspect the executable:** Determine whether the executable is legitimate and whether its location is expected.
3. **Review the account:** Identify the account associated with the service and assess whether its use is authorised.
4. **Investigate the service configuration:** Examine the service type and start type for unusual settings.
5. **Correlate additional telemetry:** Review process creation, PowerShell and authentication events around the service creation timestamp.
6. **Assess persistence:** Determine whether the service could provide an attacker with a mechanism for maintaining access.
7. **Respond appropriately:** Follow incident response procedures if malicious activity is suspected.

## Outcome

Successfully developed and validated a detection rule that identifies potentially suspicious Windows service creation activity.

This builds on the general service creation detection by introducing executable-path and process-based indicators, providing more focused visibility into potential persistence mechanisms.

