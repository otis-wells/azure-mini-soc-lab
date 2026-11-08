
# Detection 04 – Suspicious PowerShell Execution

## Overview

This detection identifies potentially suspicious PowerShell execution by analysing script block contents and correlating them with Sysmon process creation events.

PowerShell is a legitimate administrative tool but can also be abused by threat actors to execute malicious commands, download payloads, decode encoded scripts and execute code in memory.

The detection identifies suspicious command patterns, including encoded commands, execution functions and file download activity. It then correlates these findings with Sysmon process creation telemetry to provide additional context about the process and its parent process.

A risk-scoring mechanism is used to assess the observed activity and assign a severity level of Medium, High or Critical.

## Detection Configuration

| Configuration | Value |
|---|---|
| Detection Name | Suspicious PowerShell Execution |
| Data Sources | PowerShell Operational Logs / Sysmon |
| Event IDs | 4104 – PowerShell Script Block Logging / 1 – Sysmon Process Creation |
| Severity | Dynamic – Medium, High or Critical |
| MITRE ATT&CK Tactic | Execution |
| MITRE ATT&CK Technique | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Lookback Period | 30 minutes |
| Correlation Window | 10 seconds |
| Monitored Endpoint | `soc-win01` |

## Detection Logic

The query combines PowerShell script block logging with process creation telemetry to identify suspicious execution patterns.

The detection performs the following operations:

1. **Identify PowerShell activity:** Retrieves Event ID 4104 records from the previous 30 minutes.
2. **Extract script contents:** Retrieves the PowerShell script block text for analysis.
3. **Identify suspicious commands:** Searches for potentially suspicious indicators, including encoded commands, Base64 decoding, execution functions and download-related commands.
4. **Categorise suspicious behaviour:** Assigns individual indicators for encoded execution, command execution and download activity.
5. **Calculate the base risk score:** Assigns weighted values to each category, with download activity receiving the highest initial weighting.
6. **Identify process creation:** Retrieves Sysmon Event ID 1 records and extracts process details, including executable path, command line, process ID, user and parent process information.
7. **Correlate events:** Joins PowerShell script block events with process creation events from the same endpoint occurring within 10 seconds of each other.
8. **Identify suspicious parent processes:** Checks whether PowerShell was launched by potentially suspicious parent processes, including Microsoft Office applications, scripting utilities and other Windows execution tools.
9. **Calculate the final risk score:** Adds additional risk points when a suspicious parent process is identified.
10. **Assign severity:** Categorises the resulting activity according to its risk score.
11. **Present investigation details:** Returns the relevant script contents, process information, command lines, risk indicators and severity.

## Risk Scoring

The detection uses a weighted scoring mechanism to assess suspicious PowerShell activity.

| Indicator | Risk Points |
|---|---:|
| Encoded commands or Base64-related activity | +2 |
| PowerShell execution functions | +2 |
| Download-related commands | +3 |
| Suspicious parent process | +2 |

### Severity Classification

| Risk Score | Severity |
|---|---|
| 0–3 | Medium |
| 4–6 | High |
| 7–9 | Critical |

The maximum possible risk score is 9 when all four indicators are identified.

## KQL Detection Query

```kql
Event
| where TimeGenerated > ago(30m)
| where EventID == 4104
| extend ScriptBlockText = extract(
    @"<Data Name=""ScriptBlockText"">(.*?)</Data>",
    1,
    EventData
)
| where ScriptBlockText has_any (
    "-EncodedCommand",
    "-enc",
    "FromBase64String",
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "DownloadFile",
    "Start-BitsTransfer",
    "Invoke-WebRequest",
    "Net.WebClient"
)
| extend
    Encoded = iff(
        ScriptBlockText has_any (
            "-EncodedCommand",
            "-enc",
            "FromBase64String"
        ),
        1,
        0
    ),
    Execution = iff(
        ScriptBlockText has_any (
            "Invoke-Expression",
            "IEX"
        ),
        1,
        0
    ),
    Download = iff(
        ScriptBlockText has_any (
            "DownloadString",
            "DownloadFile",
            "Start-BitsTransfer",
            "Invoke-WebRequest",
            "Net.WebClient"
        ),
        1,
        0
    )
| extend BaseRiskScore = (Encoded * 2) + (Execution * 2) + (Download * 3)
| project
    PSTime = TimeGenerated,
    Computer,
    PSUser = UserName,
    ScriptBlockText,
    Encoded,
    Execution,
    Download,
    BaseRiskScore
| join kind=inner (
    Event
    | where TimeGenerated > ago(30m)
    | where EventID == 1
    | extend
        Image = extract(@"<Data Name=""Image"">(.*?)</Data>", 1, EventData),
        CommandLine = extract(@"<Data Name=""CommandLine"">(.*?)</Data>", 1, EventData),
        ProcessId = extract(@"<Data Name=""ProcessId"">(\d+)</Data>", 1, EventData),
        ProcessUser = extract(@"<Data Name=""User"">(.*?)</Data>", 1, EventData),
        ParentImage = extract(@"<Data Name=""ParentImage"">(.*?)</Data>", 1, EventData),
        ParentCommandLine = extract(@"<Data Name=""ParentCommandLine"">(.*?)</Data>", 1, EventData)
    | where Image contains "powershell.exe"
        or Image contains "pwsh.exe"
    | project
        ProcessTime = TimeGenerated,
        Computer,
        ProcessUser,
        Image,
        CommandLine,
        ProcessId,
        ParentImage,
        ParentCommandLine
) on Computer
| where abs(datetime_diff("second", PSTime, ProcessTime)) <= 10
| summarize arg_max(ProcessTime, *) by Computer, ProcessId
| extend
    SuspiciousParent = iff(
        ParentImage endswith @"\winword.exe"
        or ParentImage endswith @"\excel.exe"
        or ParentImage endswith @"\outlook.exe"
        or ParentImage endswith @"\mshta.exe"
        or ParentImage endswith @"\wscript.exe"
        or ParentImage endswith @"\cscript.exe"
        or ParentImage endswith @"\rundll32.exe"
        or ParentImage endswith @"\regsvr32.exe"
        or ParentImage endswith @"\wmic.exe"
        or ParentImage endswith @"\bitsadmin.exe",
        1,
        0
    )
| extend RiskScore = BaseRiskScore + (SuspiciousParent * 2)
| extend Severity = case(
    RiskScore >= 7, "Critical",
    RiskScore >= 4, "High",
    "Medium"
)
| project
    TimeGenerated = PSTime,
    Severity,
    RiskScore,
    Computer,
    User = PSUser,
    ProcessUser,
    ProcessId,
    Image,
    CommandLine,
    ParentImage,
    ParentCommandLine,
    ScriptBlockText,
    Encoded,
    Execution,
    Download,
    SuspiciousParent
| order by TimeGenerated desc
```

## MITRE ATT&CK Mapping

| Category | Mapping |
|---|---|
| Tactic | Execution |
| Technique | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

This detection maps to MITRE ATT&CK technique T1059.001 because it identifies potentially suspicious use of PowerShell to execute commands and scripts.

## Testing and Validation

The detection was tested within the Azure Mini-SOC environment using intentionally simulated PowerShell activity.

Validation included:

- Generating PowerShell script block logging events containing suspicious command patterns.
- Confirming that Event ID 4104 records were ingested into the Log Analytics Workspace.
- Confirming that Sysmon Event ID 1 process creation records were available.
- Verifying that the query identified the configured suspicious command indicators.
- Testing the correlation between PowerShell script block events and process creation events.
- Reviewing the risk-scoring mechanism and severity classification.
- Reviewing the returned process, user, command line and parent process information.

**Lab Validation:** All activity was intentionally simulated within the isolated lab environment.

## Recommended Response

If this detection triggers in a production environment, an analyst should:

1. Review the assigned severity and risk score.
2. Examine the PowerShell script block contents to understand the commands being executed.
3. Identify the affected user account and endpoint.
4. Investigate the executable path, process command line and parent process.
5. Determine whether encoded commands or Base64-related activity are legitimate or potentially malicious.
6. Investigate any download activity and identify the source and destination of retrieved files.
7. Correlate the activity with additional security telemetry to identify potential follow-on behaviour.
8. If malicious activity is suspected, follow the organisation's incident response procedures, including containment and further investigation.

## Outcome

Successfully demonstrated a more advanced PowerShell detection by combining script block logging with Sysmon process creation telemetry.

The implementation introduces event correlation, behavioural indicators and weighted risk scoring to provide greater investigative context than basic PowerShell activity monitoring.

The resulting severity classification helps prioritise potentially suspicious activity, while the inclusion of process and parent process information supports further investigation.
