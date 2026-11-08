
# Environment Setup

## Overview

The SOC lab was deployed using Microsoft Azure, providing the infrastructure required to host a monitored Windows endpoint and centralise security telemetry.

The environment was configured to support endpoint monitoring, security event collection and custom detection engineering.

## Azure Infrastructure

The following resources were deployed:

| Resource | Configuration |
|---|---|
| Resource Group | `rg-soc-lab` |
| Region | `swedencentral` |
| Log Analytics Workspace | `LAW-SOC-Lab1` |
| Virtual Machine | `soc-win01` |
| Monitoring Agent | Azure Monitor Agent (AMA) |

## Infrastructure Configuration

### 1. Resource Group

Created an Azure Resource Group named `rg-soc-lab` to organise and manage the resources associated with the SOC lab.

### 2. Log Analytics Workspace

Deployed a Log Analytics workspace named `LAW-SOC-Lab1` in the `swedencentral` region.

The workspace acts as the central destination for collected security telemetry and provides the foundation for querying and analysing event data.

### 3. Windows Virtual Machine

Deployed a Windows virtual machine named `soc-win01` to act as the monitored endpoint.

The virtual machine provides an environment for:

- Generating simulated authentication activity.
- Executing PowerShell commands and scripts.
- Creating Windows services.
- Producing security events for detection testing.

### 4. Azure Monitor Agent

Installed and configured the Azure Monitor Agent on `soc-win01` to facilitate the collection of endpoint telemetry.

The agent works alongside Data Collection Rules to forward configured event data to the Log Analytics workspace.

## Security Configuration

Additional monitoring capabilities were configured to improve endpoint visibility:

- Windows Security Event logging.
- PowerShell Script Block Logging.
- Sysmon endpoint telemetry.
- Azure Monitor Agent data collection.

## Outcome

The Azure infrastructure established the foundation for the SOC environment, enabling centralised log collection, security monitoring and subsequent detection engineering.

