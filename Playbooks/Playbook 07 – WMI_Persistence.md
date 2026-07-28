# Playbook 07 – WMI Persistence

## Executive Summary

Microsoft Defender XDR generated an alert indicating the creation of a new **WMI Event Subscription** on the Finance workstation **FIN-WS-022**. The activity was detected approximately **14 minutes after a previous incident involving Regsvr32 Scriptlet Abuse**.

The investigation confirmed that a permanent WMI subscription was created through three WMI objects: **__EventFilter**, **CommandLineEventConsumer**, and **__FilterToConsumerBinding**. The configured **CommandLineTemplate** was designed to execute a PowerShell script stored under **C:\ProgramData\Microsoft\update.ps1**, confirming that the attacker established persistence using a legitimate Windows management feature.

**Incident Severity:** High

---

# Objective

Investigate the suspicious WMI Event Subscription, determine whether it was used as a persistence mechanism, identify the command configured inside the WMI Consumer, and reconstruct the attack chain leading to persistence.

---

# Scenario

Microsoft Defender generated the following alert:

- **Alert Title:** Suspicious WMI Event Subscription Created
- **Device:** FIN-WS-022
- **User:** laura.sanchez
- **Severity:** Medium
- **Detection Time:** 11:17:42

The alert reported that a new permanent WMI Event Subscription was created shortly after a previously investigated Regsvr32 execution. The activity was uncommon for the endpoint and required further investigation to determine whether persistence had been established.

---

# Attack Flow Diagram

Phishing Email

↓

User opens attachment

↓

Regsvr32 Scriptlet Abuse

↓

Execution Chain

↓

wmic.exe

↓

Create __EventFilter

↓

Create CommandLineEventConsumer

↓

Create __FilterToConsumerBinding

↓

PowerShell configured as persistent payload

↓

Persistence established

---

# Timeline

| Time | Event |
|----------|--------------------------------|
|11:03:14| Regsvr32 execution begins |
|11:03:20| Additional Windows binaries executed |
|11:03:28| wmic.exe starts reconnaissance |
|11:17:31| __EventFilter created |
|11:17:34| CommandLineEventConsumer created |
|11:17:38| __FilterToConsumerBinding created |
|11:17:42| Microsoft Defender generates the alert |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---------|-----------|------|----------|
| Persistence | Windows Management Instrumentation Event Subscription | T1546.003 | Creation of **__EventFilter**, **CommandLineEventConsumer**, and **__FilterToConsumerBinding**. |
| Execution | PowerShell | T1059.001 | WMI Consumer configured to execute **powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Microsoft\update.ps1**. |
| Defense Evasion | System Binary Proxy Execution | T1218 | The attacker used legitimate Windows components instead of custom malware. |
| Discovery | System Information Discovery | T1082 | Previous execution of **wmic.exe** collected operating system information before persistence was established. |

---

# Indicators of Compromise (IOC)

| IOC | Type | Description |
|------|------|-------------|
| __EventFilter | WMI Object | Malicious WMI Event Filter created during the attack. |
| CommandLineEventConsumer | WMI Object | Stores the command executed when the event is triggered. |
| __FilterToConsumerBinding | WMI Object | Connects the Event Filter with the Consumer. |
| update.ps1 | PowerShell Script | Persistent payload stored under ProgramData. |
| C:\ProgramData\Microsoft\update.ps1 | File Path | Location used to store the PowerShell payload. |
| powershell.exe -ExecutionPolicy Bypass | Command | Command configured inside the WMI Consumer. |
| wmic.exe | Process | Used to create the WMI persistence objects. |

---

# Investigation Phases

## Phase 1 — Initial Alert Analysis

###  Question

Was the WMI Event Subscription created by legitimate administrative activity or by a suspicious execution chain?

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-022"
| where Timestamp between (datetime(2026-08-02 11:15:00)..datetime(2026-08-02 11:18:30))
| project Timestamp,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          AccountName
| order by Timestamp asc
```

###  Findings

- WMI-related processes
- Parent process
- Execution sequence
- Command-line arguments

### Analyst Interpretation

The investigation showed that **wmic.exe** executed shortly before the alert and created multiple WMI objects. The activity occurred after the previous Regsvr32 incident, strengthening the hypothesis of malicious persistence.

---

## Phase 2 — WMI Object Analysis

###  Question

What WMI objects were created during the execution?

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-022"
| where FileName == "wmic.exe"
| project Timestamp,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

###  Findings

- WMI object creation
- EventFilter
- CommandLineEventConsumer
- FilterToConsumerBinding

### Analyst Interpretation

Three WMI objects were created in sequence: **__EventFilter**, **CommandLineEventConsumer**, and **__FilterToConsumerBinding**. Together, these objects form a permanent WMI Event Subscription commonly associated with persistence.

---

## Phase 3 — Persistence Verification

###  Question

What command was configured inside the WMI Consumer?

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-022"
| where FileName == "wmic.exe"
| project Timestamp,
          ProcessCommandLine
| order by Timestamp asc
```

###  Findings

- CommandLineTemplate
- PowerShell execution
- Payload location

### Analyst Interpretation

The **CommandLineTemplate** was configured to execute:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\Microsoft\update.ps1
```

This confirmed that the WMI Consumer was configured to launch a PowerShell script automatically whenever the configured event was triggered.

---

# Threat Hunting

| Investigation Question | KQL | Purpose |
|------------------------|-----|----------|
| Have other devices created WMI Event Subscriptions? | `DeviceProcessEvents \| where FileName == "wmic.exe" \| where ProcessCommandLine has "__EventFilter"` | Identify additional endpoints where WMI persistence may have been created. |
| Have other systems created CommandLineEventConsumer objects? | `DeviceProcessEvents \| where ProcessCommandLine has "CommandLineEventConsumer"` | Detect similar persistence mechanisms across the environment. |
| Have other endpoints executed update.ps1? | `DeviceProcessEvents \| where ProcessCommandLine has "update.ps1"` | Identify execution of the same payload on other devices. |
| Have other PowerShell processes used ExecutionPolicy Bypass? | `DeviceProcessEvents \| where ProcessCommandLine has "-ExecutionPolicy Bypass"` | Detect suspicious PowerShell executions. |
| Have other devices created files under ProgramData after WMI activity? | `DeviceFileEvents \| where FolderPath has @"C:\ProgramData"` | Identify additional persistence-related artifacts. |

---

# Containment Actions

- Isolate the affected endpoint.
- Preserve forensic evidence before remediation.
- Remove the malicious WMI Event Subscription.
- Delete the malicious PowerShell script after evidence collection.
- Reset the affected user's credentials.
- Block any infrastructure associated with the previous phishing campaign.
- Escalate the incident to Tier 2 for forensic validation.

---

# Detection Opportunities

- Detect creation of **__EventFilter** objects.
- Alert on **CommandLineEventConsumer** creation.
- Monitor the use of **__FilterToConsumerBinding**.
- Detect **PowerShell** executed through **CommandLineTemplate**.
- Monitor **wmic.exe** creating WMI objects outside normal administrative activity.
- Alert on **PowerShell -ExecutionPolicy Bypass** executed from **ProgramData**.

---

# Lessons Learned

- WMI is a legitimate Windows management feature that can be abused to establish stealthy persistence.
- WMI persistence does not require Scheduled Tasks or Windows Services.
- Attackers often combine LOLBins with WMI to reduce detection.
- Correlating multiple alerts was essential to reconstruct the complete attack chain.
- Understanding WMI objects and their relationships allows analysts to identify persistence mechanisms more effectively.