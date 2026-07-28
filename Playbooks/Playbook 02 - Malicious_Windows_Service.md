# Malicious Windows Service with Rundll32 Persistence and Suspected C2 Communication

## 1. Executive Summary

A Windows endpoint generated an alert after the installation of a suspicious Windows service followed by repeated outbound network connections.

The investigation revealed that a batch script created a malicious persistence mechanism by installing a Windows service named **WindowsUpdateMonitor**, configured to execute **rundll32.exe** with a DLL stored in **C:\ProgramData\WindowsUpdate\updatemonitor.dll**.

After the service was installed, the DLL established periodic outbound HTTPS connections to an external host approximately every 30 seconds, showing a beaconing pattern consistent with suspected Command and Control (C2) activity. The compromised process also attempted SMB connections to additional internal hosts, indicating possible lateral movement attempts.

Threat hunting activities did not identify additional compromised endpoints, suggesting the incident was limited to a single device.

---

# 2. Objective

Investigate a suspicious Windows service installation, determine how persistence was established, identify related network activity, evaluate the scope of the incident, and recommend containment actions.

---

# 3. Scenario

A Microsoft Defender XDR alert reported the installation of a suspicious Windows service followed by outbound network connections from workstation **OPS-WS-023**.

Initial investigation focused on identifying:

- The process responsible for creating the service.
- The origin of the DLL used by the service.
- Associated network communications.
- Potential lateral movement.
- Whether additional endpoints were affected.

---

# 4. Attack Flow Diagram

```text
Explorer.exe
      │
      ▼
install_update.bat
      │
      ▼
cmd.exe
      │
      ▼
Copy updatemonitor.dll
to ProgramData
      │
      ▼
sc.exe
Create Windows Service
      │
      ▼
WindowsUpdateMonitor
      │
      ▼
services.exe
      │
      ▼
rundll32.exe
Loads updatemonitor.dll
      │
      ▼
Outbound HTTPS Connections
      │
      ▼
Suspected C2 Beaconing
      │
      ▼
SMB Connections to Internal Hosts
```

---

# 5. Timeline

| Time | Event |
|------|-------|
|08:38:51|User executed **install_update.bat** from Downloads.|
|08:38:55|DLL copied to **ProgramData\\WindowsUpdate**.|
|08:39:14|Windows service **WindowsUpdateMonitor** created using **sc.exe**.|
|08:39:16|Service started **rundll32.exe** to execute the DLL.|
|08:39:17|First outbound HTTPS connection to **185.231.72.44**.|
|08:39:47 - 08:42:17|Repeated outbound connections every 30 seconds (beaconing pattern).|
|08:42:21|Successful SMB connection to internal host **10.10.15.25**.|
|08:42:24|Failed SMB connection to **10.10.15.31**.|

---

# 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Defense Evasion | Signed Binary Proxy Execution: Rundll32 | T1218.011 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |

---

# 7. Indicators of Compromise (IOC)

## IP Addresses

- 185.231.72.44
- 10.10.15.25
- 10.10.15.31

## Domain

- update-check-storage.com

## Service

- WindowsUpdateMonitor

## Files

- install_update.bat
- updatemonitor.dll

## Processes

- cmd.exe
- sc.exe
- rundll32.exe

## File Paths

- C:\Users\soporte.local\Downloads\
- C:\ProgramData\WindowsUpdate\updatemonitor.dll

---

# 8. Investigation Phases

---

## Phase 1 – Initial Process Investigation

### Objective

Determine which process initiated the suspicious activity and identify how the Windows service was created.

### Why DeviceProcessEvents?

This table records process execution events, making it the best starting point for reconstructing the process tree and identifying the parent-child relationship that led to the service installation.

### KQL

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-07-14 08:20:00) .. datetime(2026-07-14 08:50:00))
| where DeviceName == "OPS-WS-023"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Findings

The investigation identified the following execution chain:

```text
explorer.exe
      ↓
cmd.exe
      ↓
sc.exe
      ↓
services.exe
      ↓
rundll32.exe
```

The analysis confirmed that **sc.exe** created a new Windows service named **WindowsUpdateMonitor**, configured to execute **rundll32.exe** with a DLL stored in **ProgramData**, indicating persistence.

### Investigation Decision

At this stage, the service creation strongly suggested malicious persistence. The next step was to investigate how the DLL reached the endpoint.

---

## Phase 2 – File Investigation

### Objective

Determine the origin of the DLL and identify whether additional files were created or modified before the service installation.

### Why DeviceFileEvents?

This table records file creation, modification, and access events, allowing us to reconstruct the lifecycle of the malicious DLL.

### KQL

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-07-14 08:20:00) .. datetime(2026-07-14 08:50:00))
| where DeviceName == "OPS-WS-023"
| project Timestamp,
          DeviceName,
          ActionType,
          FileName,
          FolderPath,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Findings

The DLL was initially located in the user's Downloads folder before being copied to **C:\ProgramData\WindowsUpdate**.

The service later executed the DLL from this location using **rundll32.exe**.

### Investigation Decision

The file activity confirmed that the attacker intentionally relocated the DLL to a less suspicious directory before establishing persistence.

The next investigation focused on network communications.

---

## Phase 3 – Network Investigation

### Objective

Determine whether the malicious DLL established outbound communications.

### Why DeviceNetworkEvents?

This table records outbound and inbound network activity, making it possible to identify Command and Control communications and beaconing behavior.

### KQL

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-07-14 08:20:00) .. datetime(2026-07-14 08:50:00))
| where DeviceName == "OPS-WS-023"
| project Timestamp,
          DeviceName,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Findings

Multiple successful outbound HTTPS connections were established to **185.231.72.44** approximately every 30 seconds.

The same process (**rundll32.exe**) executed the malicious DLL during every connection.

Additional SMB connections toward internal hosts were also observed.

### Investigation Decision

The communication pattern was highly consistent with beaconing behavior and suggested possible Command and Control activity together with attempted lateral movement.

The incident severity was raised to **High**.

---

## Phase 4 – Threat Hunting

### Objective

Determine whether additional endpoints had been compromised.

### Hunting Question 1

**Are other endpoints communicating with the same external IP?**

### KQL

```kql
DeviceNetworkEvents
| where RemoteIP == "185.231.72.44"
| project Timestamp,
          DeviceName,
          AccountName,
          RemoteIP,
          RemotePort,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Result

No additional endpoints communicated with the external IP.

---

### Hunting Question 2

**Has the Windows service been created on other endpoints?**

### KQL

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "WindowsUpdateMonitor"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

### Result

The service was only found on **OPS-WS-023**.

---

### Hunting Question 3

**Is the DLL being executed on other endpoints?**

### KQL

```kql
DeviceProcessEvents
| where FileName == "rundll32.exe"
| where ProcessCommandLine contains "updatemonitor.dll"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine
```

### Result

No additional executions were identified.

---

### Hunting Question 4

**Does the DLL exist on other devices?**

### KQL

```kql
DeviceFileEvents
| where FileName == "updatemonitor.dll"
| project Timestamp,
          DeviceName,
          FolderPath,
          ActionType,
          InitiatingProcessFileName
```

### Result

The DLL was only present on the affected endpoint.

### Final Hunting Assessment

Based on the available telemetry, the compromise appeared to be limited to a single endpoint.

---

# 9. Containment Actions

- Isolate the affected endpoint.
- Escalate the incident to the SOC L2 / Incident Response team.
- Block the external IP address and associated domain.
- Preserve forensic evidence before removing the malicious service.
- Remove the malicious Windows service after evidence collection.
- Monitor the environment for additional related activity.

---

# 10. Threat Hunting

Recommended enterprise-wide hunting activities:

- Search for devices communicating with **185.231.72.44**.
- Search for executions of **rundll32.exe** loading **updatemonitor.dll**.
- Search for the **WindowsUpdateMonitor** service.
- Search for the presence of **updatemonitor.dll** in ProgramData.
- Search for similar beaconing patterns.

---

# 11. Detection Opportunities

- Alert on new Windows service creation using **sc.exe**.
- Detect **rundll32.exe** loading DLLs from non-standard directories.
- Monitor DLL creation within **ProgramData**.
- Detect periodic outbound connections from the same process.
- Alert on SMB connections initiated shortly after suspicious service creation.

---

# 12. Lessons Learned

- Monitor Windows service creation more closely.
- Restrict unnecessary service creation privileges.
- Improve monitoring of DLL execution from uncommon directories.
- Implement detections for beaconing behavior.
- Review endpoint protection policies for LOLBin abuse.
- Regularly perform threat hunting for persistence mechanisms.

---