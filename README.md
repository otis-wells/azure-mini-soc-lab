
<h1 align="center">Azure Mini-SOC Lab</h1>

<p align="center">
  A hands-on Security Operations Centre (SOC) project built using Microsoft Azure, focused on security monitoring, threat detection and incident investigation.
</p>

---

<h2>Project Overview</h2>

<p>
This project involved designing and deploying a simulated SOC environment in Azure to explore real-world security monitoring and detection engineering.
</p>

<p>
Using Microsoft Sentinel, Azure Log Analytics, Microsoft Defender and a Windows virtual machine, I configured security event collection, developed custom detection rules and simulated suspicious activity to generate alerts for investigation.
</p>

<p>
The project demonstrates practical experience in identifying suspicious behaviour, analysing security events, mapping detections to the MITRE ATT&CK framework and recommending appropriate incident response actions.
</p>


<h2>Documentation</h2>

<ul>
  <li><a href="documentation/architecture.md">SOC Architecture</a></li>
  <li><a href="documentation/environment-setup.md">Environment Setup</a></li>
  <li><a href="documentation/data-collection.md">Data Collection</a></li>
  <li><a href="documentation/detection-engineering.md">Detection Engineering</a></li>
</ul>


<h2>Technology Stack</h2>

<table>
  <thead>
    <tr>
      <th>Technology</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Microsoft Azure</td>
      <td>Cloud infrastructure</td>
    </tr>
    <tr>
      <td>Microsoft Sentinel / Defender</td>
      <td>SIEM and security monitoring</td>
    </tr>
    <tr>
      <td>Azure Log Analytics</td>
      <td>Centralised log collection and analysis</td>
    </tr>
    <tr>
      <td>Windows Virtual Machine</td>
      <td>Simulated endpoint environment</td>
    </tr>
    <tr>
    <tr>
      <td>Sysmon</td>
      <td>Enhanced endpoint telemetry</td>
    </tr>
    <tr>
      <td>Kusto Query Language (KQL)</td>
      <td>Detection rule development</td>
    </tr>
  </tbody>
</table>

<h2>Detection Engineering</h2>

<p>
Six custom detection scenarios were developed and validated using simulated security activity.
</p>

<table>
  <thead>
    <tr>
      <th>Detection</th>
      <th>MITRE ATT&CK</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Multiple failed logon attempts</td>
      <td>T1110 – Brute Force</td>
    </tr>
    <tr>
      <td>Failed logon followed by successful authentication</td>
      <td>T1110 – Brute Force</td>
    </tr>
    <tr>
      <td>PowerShell Executions</td>
      <td>T1059.001 – PowerShell</td>
    </tr>
    <tr>
      <td>Suspicious PowerShell execution</td>
      <td>T1059.001 – PowerShell</td>
    </tr>
    <tr>
      <td>Windows service creation</td>
      <td>T1543.003 – Windows Service</td>
    </tr>
    <tr>
      <td>Suspicious service creation</td>
      <td>T1543.003 – Windows Service</td>
    </tr>
  </tbody>
</table>

<h2>Incident Investigation</h2>

<p>
Generated alerts were investigated to understand the underlying activity, assess potential security implications and establish appropriate response recommendations.
</p>

<p>The investigation documents:</p>

<ul>
  <li>Alert identification and initial triage</li>
  <li>Relevant security event analysis</li>
  <li>Investigation findings and supporting evidence</li>
  <li>MITRE ATT&CK technique mapping</li>
  <li>Recommended incident response actions</li>
  <li>Lab validation and testing results</li>
</ul>

<p>
<strong>Note:</strong> All malicious or suspicious activity was intentionally simulated within the lab environment.
</p>

<h2>Skills Demonstrated</h2>

<ul>
  <li>SIEM configuration and security monitoring</li>
  <li>Log collection and analysis</li>
  <li>KQL detection engineering</li>
  <li>Windows security event analysis</li>
  <li>PowerShell activity monitoring</li>
  <li>Threat detection and incident triage</li>
  <li>MITRE ATT&CK framework mapping</li>
  <li>Incident investigation and response documentation</li>
  <li>Azure cloud infrastructure configuration</li>
</ul>

<h2>Repository Structure</h2>

<pre>
azure-mini-soc-lab/
│
├── README.md
│
├── documentation/
│   ├── architecture.md
│   ├── environment-setup.md
│   ├── data-collection.md
│   └── detection-engineering.md
│
├── detection-rules/
│   ├── failed-logon-attempts.md
│   ├── brute-force-successful-logon.md
│   ├── powershell-execution.md
│   ├── suspicious-powershell.md
│   ├── service-creation.md
│   └── suspicious-service-creation.md
│
├── incident-reports/
│
├── screenshots/
│   ├── configuration/
│   ├── analytics-rules/
│   └── alert-evidence/

</pre>

<h2>Project Status</h2>

<p>
  <strong>Completed</strong> – All six detection scenarios successfully developed, tested and validated within the simulated SOC environment.
</p>

<p>
Future improvements may include additional detection scenarios, automated response capabilities and expanded endpoint telemetry.
</p>
