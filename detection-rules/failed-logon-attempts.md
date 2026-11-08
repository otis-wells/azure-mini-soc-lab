
# Detection 01 – Multiple Failed Logon Attempts

## Overview

This detection identifies repeated failed authentication attempts against a Windows endpoint.

Multiple failed logons may indicate brute-force activity, password guessing or attempts to gain unauthorised access.

The detection uses Windows Security Event ID 4625 and custom KQL logic to extract authentication metadata, identify failure patterns and generate an investigation-friendly alert summary.

## Detection Configuration

| Setting | Value |
|---|---|
| Detection Name | Multiple Failed Logon Attempts |
| Data Source | Windows Security Events |
| Event ID | 4625 |
| Severity | Low |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1110 – Brute Force |
| Detection Threshold | 3 or more failures |
| Time Window | 5 minutes |
| Monitored Endpoint | soc-win01 |

## Detection Logic

The detection monitors Windows Security Event ID 4625, which records failed authentication attempts.

KQL is used to extract relevant authentication metadata from the event data, including:

- Target username.
- Source IP address.
- Logon type.
- Workstation name.
- Authentication package.
- Windows authentication status and substatus codes.
- Failure reason.

Additional logic translates Windows authentication substatus codes into human-readable descriptions, helping distinguish between scenarios such as incorrect passwords, non-existent accounts and locked accounts.

Logon types are also translated into descriptive categories, providing additional context about the authentication method.

The query groups failed authentication events by endpoint, target username, source IP address and five-minute time window.

An alert condition is met when three or more failed logons are identified within that window.

A descriptive summary is generated to provide an initial overview of the authentication activity and support subsequent investigation.

## KQL Query

```kql
Event
| where EventID == 4625
| extend
    TargetUserName = extract(@"<Data Name=""TargetUserName"">(.*?)</Data>", 1, EventData),
    IpAddress = extract(@"<Data Name=""IpAddress"">(.*?)</Data>", 1, EventData),
    LogonType = extract(@"<Data Name=""LogonType"">(.*?)</Data>", 1, EventData),
    WorkstationName = extract(@"<Data Name=""WorkstationName"">(.*?)</Data>", 1, EventData),
    AuthenticationPackage = extract(@"<Data Name=""AuthenticationPackageName"">(.*?)</Data>", 1, EventData),
    Status = extract(@"<Data Name=""Status"">(.*?)</Data>", 1, EventData),
    SubStatus = extract(@"<Data Name=""SubStatus"">(.*?)</Data>", 1, EventData),
    FailureReason = extract(@"<Data Name=""FailureReason"">(.*?)</Data>", 1, EventData)
| extend
    FailureDescription = case(
        SubStatus == "0xc0000064", "Account does not exist",
        SubStatus == "0xc000006a", "Incorrect password",
        SubStatus == "0xc0000234", "Account locked out",
        SubStatus == "0xc0000072", "Account disabled",
        "Other authentication failure"
    ),
    LogonTypeDescription = case(
        LogonType == "2", "Interactive",
        LogonType == "3", "Network",
        LogonType == "4", "Batch",
        LogonType == "5", "Service",
        LogonType == "7", "Unlock",
        LogonType == "8", "NetworkCleartext",
        LogonType == "9", "NewCredentials",
        LogonType == "10", "RemoteInteractive (RDP)",
        LogonType == "11", "CachedInteractive",
        "Other"
    )
| summarize
    FailedLogons = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    LogonTypes = make_set(LogonType),
    LogonTypeDescriptions = make_set(LogonTypeDescription),
    AuthenticationPackages = make_set(AuthenticationPackage),
    FailureReasons = make_set(FailureReason),
    FailureDescriptions = make_set(FailureDescription),
    Statuses = make_set(Status),
    SubStatuses = make_set(SubStatus),
    Workstations = make_set(WorkstationName)
    by Computer, TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where FailedLogons >= 3
| extend Summary = strcat(
    tostring(FailedLogons),
    " failed ",
    tostring(LogonTypeDescriptions[0]),
    " logons for ",
    tostring(TargetUserName),
    " from ",
    tostring(IpAddress),
    " against ",
    tostring(Computer),
    ". Authentication: ",
    tostring(AuthenticationPackages[0]),
    ". Failure: ",
    tostring(FailureDescriptions[0]),
    "."
)
```

## MITRE ATT&CK Mapping

| Category | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |

This detection supports the identification of repeated authentication attempts that may indicate password guessing or brute-force activity.

## Testing and Validation

The detection was tested using intentionally simulated authentication failures against the Windows virtual machine.

Testing involved generating repeated failed logon attempts using a dedicated lab test account.

The resulting Event ID 4625 records were collected and ingested into the Log Analytics workspace.

The detection query was then evaluated to verify that:

- Failed authentication events were successfully identified.
- Relevant authentication metadata was extracted.
- Failure descriptions and logon types were translated.
- Events were grouped within the configured five-minute window.
- The threshold of three or more failures was met.
- The resulting detection provided useful information for investigation.

## Recommended Response

1. Identify the affected account and monitored endpoint.
2. Review the source IP address and associated workstation information.
3. Examine authentication failure descriptions and Windows status codes.
4. Investigate the frequency and timing of failed authentication attempts.
5. Review subsequent successful authentication events for the affected account.
6. Determine whether the activity is legitimate or potentially malicious.
7. Consider account protection measures and escalate where appropriate.

## Outcome

The detection successfully demonstrated the identification of repeated failed authentication attempts within the simulated SOC environment.

The additional KQL logic provides enriched authentication context, improving the usefulness of generated alerts and supporting more effective initial investigation and triage.
