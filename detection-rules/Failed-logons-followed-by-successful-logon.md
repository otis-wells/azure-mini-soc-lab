
# Detection 02 – Failed Logons Followed by Successful Authentication

## Overview

This detection identifies potentially suspicious authentication activity where multiple failed logon attempts are followed by a successful authentication to the same account on the same Windows endpoint.

This behaviour may indicate a successful brute-force or password-guessing attempt, where an attacker eventually obtains valid credentials.

The detection correlates Windows Security Event ID 4625 (failed logon) with Event ID 4624 (successful logon), identifying three or more failed attempts within the 15 minutes preceding a successful authentication.

## Detection Configuration

| Configuration | Value |
|---|---|
| Detection Name | Failed Logons Followed by Successful Authentication |
| Data Source | Windows Security Events |
| Event IDs | 4625 – Failed Logon / 4624 – Successful Logon |
| Severity | Medium |
| MITRE ATT&CK Tactic | Credential Access |
| MITRE ATT&CK Technique | T1110 – Brute Force |
| Failure Threshold | 3 or more failed logons |
| Correlation Window | 15 minutes |
| Monitored Endpoint | `soc-win01` |

## Detection Logic

The query uses event correlation to identify successful authentication following repeated failed logon attempts.

The detection performs the following operations:

1. **Identify successful logons:** Retrieves Event ID 4624 records and extracts the target username, source IP address, logon type and authentication package.
2. **Identify failed logons:** Retrieves Event ID 4625 records and extracts the corresponding authentication details.
3. **Correlate authentication events:** Joins successful and failed logons using the computer name and target username.
4. **Apply the time condition:** Checks that failed attempts occurred before the successful authentication and within the preceding 15 minutes.
5. **Count failed attempts:** Groups the correlated events and counts the number of failed authentication attempts.
6. **Apply the threshold:** Returns results where three or more failed attempts occurred before a successful logon.
7. **Enrich the results:** Calculates the time between the last failed attempt and successful authentication, while retaining relevant account, endpoint, IP address and authentication information.
8. **Identify entities:** Creates host, account and IP entity fields to support investigation and alert enrichment.

## KQL Detection Query

```kql
Event
| where EventID == 4624
| extend
    TargetUserName = extract(@"<Data Name=""TargetUserName"">(.*?)</Data>", 1, EventData),
    SuccessIpAddress = extract(@"<Data Name=""IpAddress"">(.*?)</Data>", 1, EventData),
    SuccessLogonType = extract(@"<Data Name=""LogonType"">(.*?)</Data>", 1, EventData),
    SuccessAuthenticationPackage = extract(@"<Data Name=""AuthenticationPackageName"">(.*?)</Data>", 1, EventData)
| join kind=inner (
    Event
    | where EventID == 4625
    | extend
        TargetUserName = extract(@"<Data Name=""TargetUserName"">(.*?)</Data>", 1, EventData),
        FailedIpAddress = extract(@"<Data Name=""IpAddress"">(.*?)</Data>", 1, EventData),
        FailedLogonType = extract(@"<Data Name=""LogonType"">(.*?)</Data>", 1, EventData),
        FailedAuthenticationPackage = extract(@"<Data Name=""AuthenticationPackageName"">(.*?)</Data>", 1, EventData)
    | project
        FailedTime = TimeGenerated,
        Computer,
        TargetUserName,
        FailedIpAddress,
        FailedLogonType,
        FailedAuthenticationPackage
) on Computer, TargetUserName
| where FailedTime < TimeGenerated
| where TimeGenerated <= FailedTime + 15m
| summarize
    FailedCount = count(),
    FirstFailed = min(FailedTime),
    LastFailed = max(FailedTime),
    FailedIPs = make_set(FailedIpAddress),
    FailedLogonTypes = make_set(FailedLogonType),
    FailedAuthenticationPackages = make_set(FailedAuthenticationPackage),
    SuccessTime = max(TimeGenerated),
    SuccessIpAddress = any(SuccessIpAddress),
    SuccessLogonType = any(SuccessLogonType),
    SuccessAuthenticationPackage = any(SuccessAuthenticationPackage)
    by Computer, TargetUserName
| where FailedCount >= 3
| extend
    TimeToSuccess = SuccessTime - LastFailed
| extend
    HostEntity = tostring(Computer),
    AccountEntity = tostring(TargetUserName),
    IpEntity = tostring(SuccessIpAddress)
| project
    SuccessTime,
    HostEntity,
    AccountEntity,
    IpEntity,
    Computer,
    TargetUserName,
    SuccessIpAddress,
    FailedCount,
    FirstFailed,
    LastFailed,
    TimeToSuccess,
    FailedIPs,
    SuccessLogonType,
    SuccessAuthenticationPackage
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---|---|---|
| Credential Access | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) |

This detection is associated with MITRE ATT&CK technique T1110 because repeated failed authentication attempts followed by a successful logon may indicate an attacker has successfully guessed or obtained valid credentials.

## Testing and Validation

The detection was tested within the Azure Mini-SOC environment using intentionally simulated authentication activity.

Validation included:

- Generating multiple failed authentication attempts using a lab test account.
- Successfully authenticating to the same account afterwards.
- Confirming that Event IDs 4625 and 4624 were ingested.
- Verifying that the query correlated the failed and successful events.
- Confirming that the three-failure threshold and 15-minute correlation window were applied.
- Reviewing the returned account, endpoint, IP address and timing information.

**Lab Validation:** All activity was intentionally simulated within the isolated lab environment.

## Recommended Response

If this detection triggers in a production environment, an analyst should:

1. Review the affected account and endpoint.
2. Investigate the failed authentication attempts, including their source IP addresses and frequency.
3. Compare the source IP addresses of failed attempts with the successful authentication.
4. Review the successful logon's time, logon type and authentication package.
5. Investigate whether the successful authentication was expected and authorised.
6. Check for subsequent suspicious activity, including privilege escalation, lateral movement or unusual account behaviour.
7. If compromise is suspected, follow the organisation's incident response procedures, including account protection and credential resets where appropriate.

## Outcome

Successfully demonstrated the correlation of repeated failed authentication attempts with a subsequent successful logon.

The detection provides additional investigative context by identifying the affected account, endpoint, source IP address and timing of authentication events. This helps an analyst prioritise potentially compromised credentials for further investigation.
