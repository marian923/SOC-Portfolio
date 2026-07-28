# Playbook 06 – Regsvr32 Scriptlet Abuse

## Executive Summary

Microsoft Defender XDR generated an alert indicating suspicious outbound network activity initiated by **regsvr32.exe** on the Finance workstation **FIN-WS-022**. The investigation revealed that shortly after the user opened an email attachment received from a trusted supplier, **regsvr32.exe** executed using uncommon command-line parameters to retrieve a remote **Scriptlet (.sct)** file.

Further analysis showed that the downloaded script triggered a staged execution chain involving legitimate Windows binaries (**cmd.exe**, **mshta.exe**, **rundll32.exe**, and **wmic.exe**), while creating additional artifacts under the user's temporary directory.

Although persistence was not confirmed during this investigation, evidence suggested possible follow-up activity related to Windows Management Instrumentation (WMI), requiring additional investigation.

**Incident Severity:** High

---

# Objective

Investigate suspicious execution of **regsvr32.exe**, determine whether it was abused to execute remote code, reconstruct the execution chain, identify Indicators of Compromise (IOCs), and determine whether additional attacker activity occurred on the endpoint.

---

# Scenario

Microsoft Defender generated the following alert:

- **Alert Title:** Suspicious Regsvr32 Network Activity
- **Device:** FIN-WS-022
- **User:** laura.sanchez
- **Severity:** Medium
- **Detection Time:** 11:03:14

The alert reported that **regsvr32.exe** established outbound network communication using uncommon command-line arguments immediately after the Finance user opened an email attachment received from a known supplier.

---

# Attack Flow Diagram
```text
Outlook Email

    ↓

User opens attachment

    ↓

regsvr32.exe

    ↓

Downloads remote Scriptlet (invoice.sct)

    ↓

scrobj.dll processes Scriptlet

    ↓

cmd.exe

    ↓   

mshta.exe

    ↓

rundll32.exe

    ↓

wmic.exe

    ↓

Additional artifacts created

    ↓

Possible WMI-related activity identified
```
---

# Timeline

| Time | Event |
|----------|--------------------------------|
|11:03:13| Outlook launches regsvr32.exe |
|11:03:14| regsvr32.exe retrieves remote Scriptlet |
|11:03:15| invoice.sct created in Temp folder |
|11:03:15| invoice.sct modified |
|11:03:16| invoice.sct read by scrobj.dll |
|11:03:17| cmd.exe executed |
|11:03:20| mshta.exe launched |
|11:03:24| rundll32.exe executed |
|11:03:28| wmic.exe queried operating system information |
|11:03:29| wmi_update.log created under ProgramData |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---------|-----------|------|----------|
| Execution | Regsvr32 | T1218.010 | `regsvr32.exe` executed using uncommon command-line arguments with the `/i:` parameter pointing to a remote Scriptlet (`invoice.sct`). |
| Defense Evasion | System Binary Proxy Execution | T1218 | Legitimate Windows binaries (`regsvr32.exe`, `mshta.exe`, `rundll32.exe`) were abused to execute attacker-controlled code while blending with normal system activity. |
| Execution | Signed Binary Proxy Execution | T1218 | The attacker leveraged trusted Microsoft binaries instead of deploying a custom executable. |
| Discovery | System Information Discovery | T1082 | `wmic.exe` queried the operating system version using `wmic os get Caption,Version`. |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `regsvr32.exe` established outbound communication with `cdn-storage-sync.com` to retrieve remote content over HTTP/HTTPS. |

---

# Indicators of Compromise (IOC)

| IOC | Type | Description |
|------|------|-------------|
| cdn-storage-sync.com | Domain | Remote infrastructure contacted during execution |
| invoice.sct | File | Remote Scriptlet downloaded and processed by regsvr32 |
| update.hta | File | Secondary payload executed through mshta.exe |
| wmi_update.log | File | Suspicious artifact created under ProgramData requiring additional investigation |
| regsvr32.exe | Process | LOLBin abused to execute remote Scriptlet |
| scrobj.dll | DLL | Legitimate Windows component used to process Scriptlet files |
| mshta.exe | Process | Used during staged execution |
| rundll32.exe | Process | Legitimate Windows utility used during execution chain |
| wmic.exe | Process | Queried operating system information after execution |

---

# Investigation Phases

## Phase 1 — Initial Alert Analysis

###  Question

Was **regsvr32.exe** legitimately executed or abused to retrieve remote content?

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-022"
| where FileName == "regsvr32.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

###  Findings

- Complete command line
- Parent process
- Execution sequence
- Suspicious parameters

### Analyst Interpretation

The investigation confirmed that **Outlook** initiated **regsvr32.exe**, which executed using uncommon command-line arguments and referenced a remote **Scriptlet (.sct)** through the **/i:** parameter.

---

## Phase 2 — File Activity Analysis

###  Question

Did regsvr32 create or manipulate any files during execution?

### KQL

```kql
DeviceFileEvents
| where DeviceName == "FIN-WS-022"
| where InitiatingProcessFileName in ("regsvr32.exe","mshta.exe","rundll32.exe")
| project Timestamp,
          ActionType,
          FileName,
          FolderPath,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

###  Findings

- File creation
- File modification
- File read operations
- File locations

### Analyst Interpretation

The investigation identified the creation, modification and execution of **invoice.sct** inside the user's temporary directory, indicating automated processing immediately after download. Additional artifacts (**update.hta** and **wmi_update.log**) suggested that the attack continued through multiple execution stages.

---

## Phase 3 — Execution Chain Reconstruction

###  Question

What processes were executed after the Scriptlet was processed?

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-022"
| where Timestamp between (datetime(2026-08-02 11:03:14)..datetime(2026-08-02 11:04:00))
| project Timestamp,
          FileName,
          InitiatingProcessFileName,
          ProcessCommandLine
| order by Timestamp asc
```

###  Findings

- Child processes
- Execution sequence
- Living-off-the-Land binaries

### Analyst Interpretation

The Scriptlet initiated a staged execution chain involving **cmd.exe**, **mshta.exe**, **rundll32.exe**, and **wmic.exe**. The exclusive use of legitimate Windows binaries suggests an attempt to blend malicious activity with normal operating system behavior while reducing the likelihood of detection.

---


# Threat Hunting

| Investigation Question | KQL | Purpose |
|------------------------|-----|----------|
| Have other devices executed `regsvr32.exe` with remote URLs? | ```DeviceProcessEvents \| where FileName == "regsvr32.exe" \| where ProcessCommandLine has "http"``` | Identify additional endpoints potentially affected by the same execution technique. |
| Has the domain `cdn-storage-sync.com` been contacted by other devices? | ```DeviceNetworkEvents \| where RemoteUrl contains "cdn-storage-sync.com"``` | Determine whether other hosts communicated with the same attacker infrastructure. |
| Have other Scriptlet files (`.sct`) been created across the environment? | ```DeviceFileEvents \| where FileName endswith ".sct"``` | Detect additional Scriptlet downloads or executions. |
| Have other users executed `mshta.exe` shortly after `regsvr32.exe`? | ```DeviceProcessEvents \| where FileName == "mshta.exe"``` | Identify similar LOLBin execution chains in other endpoints. |
| Have other systems executed `wmic.exe` immediately after `regsvr32.exe`? | ```DeviceProcessEvents \| where FileName == "wmic.exe"``` | Identify possible follow-on discovery activity after Scriptlet execution. |

---
# Containment Actions

- Isolate the affected endpoint.
- Block communication with **cdn-storage-sync.com**.
- Preserve forensic evidence before remediation.
- Remove downloaded Scriptlet and related artifacts after evidence collection.
- Reset user credentials if compromise is confirmed.
- Escalate the incident to Tier 2 for advanced investigation.

---

# Detection Opportunities

- Detect **regsvr32.exe** executing with remote URLs.
- Monitor execution using the **/i:** parameter.
- Alert when **regsvr32.exe** launches **mshta.exe**, **cmd.exe**, or **rundll32.exe**.
- Detect Scriptlet (.sct) creation within user Temp directories.
- Identify unusual outbound connections initiated by **regsvr32.exe**.

---

# Lessons Learned

- Legitimate Windows binaries can be abused to execute malicious code without dropping traditional malware.
- Correlating process execution, file activity, and network communication is essential to reconstruct the full attack chain.
- Temporary folders should not be ignored during endpoint investigations.
- Execution through LOLBins often leaves subtle artifacts that require behavioral analysis rather than signature-based detection.
- The appearance of **WMI-related artifacts** justified opening a dedicated follow-up investigation focused on persistence techniques.