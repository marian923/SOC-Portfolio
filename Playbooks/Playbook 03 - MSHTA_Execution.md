# Investigation of Suspicious MSHTA Execution with PowerShell and Beaconing Activity

# 1. Executive Summary

A Microsoft Defender XDR alert detected the execution of **mshta.exe** on endpoint **FIN-WS-014**. The investigation revealed that an HTA file launched an obfuscated PowerShell command, which performed system and account discovery before establishing repeated outbound HTTPS connections to an external domain.

Further analysis identified the creation of additional PowerShell artifacts within the user's temporary directory, indicating that the attacker deployed an intermediate payload after the initial execution.

The observed behavior was consistent with a multi-stage attack involving execution, discovery, and suspected Command and Control (C2) communications. The incident was assessed as **High Severity** and required immediate containment and escalation to the SOC Level 2 team.

# 2. Objective

Investigate the execution of **mshta.exe** detected by Microsoft Defender XDR to determine whether the activity was legitimate or malicious.

The investigation focused on reconstructing the attack chain, identifying attacker behavior, confirming Command and Control communications, collecting Indicators of Compromise (IOCs), mapping the activity to the MITRE ATT&CK framework, and defining appropriate containment actions.

# 3. Scenario

Microsoft Defender XDR generated a medium-severity alert after detecting the execution of **mshta.exe** on endpoint **FIN-WS-014** under the user **j.smith**.

The process was executed from the user's context and generated several child processes, including an obfuscated PowerShell command. Initial telemetry suggested possible malicious activity; however, additional investigation was required to determine whether the execution was part of legitimate business operations or an active compromise.

The investigation aimed to determine the full attack chain, identify any persistence or payload deployment, and assess whether the endpoint established external communications indicative of Command and Control activity.

# 4. Attack Flow Diagram

```text
User Execution
      │
      ▼
Invoice_Review.hta
      │
      ▼
mshta.exe
      │
      ▼
PowerShell (-nop -w hidden -enc)
      │
      ▼
Discovery Commands
│
├── whoami
├── hostname
├── ipconfig /all
├── net user
└── nltest /dclist
      │
      ▼
Creation of stage1.ps1
      │
      ▼
Outbound HTTPS Connections
      │
      ▼
Suspected Command & Control
```

# 5. Timeline

| Time | Event |
|------|-------|
|10:14:26|`mshta.exe` executed `Invoice_Review.hta` from the user's Downloads folder.|
|10:14:28|`mshta.exe` launched an obfuscated PowerShell process using `-nop`, `-w hidden`, and `-enc`.|
|10:14:31|PowerShell executed `whoami` to identify the current user.|
|10:14:32|PowerShell executed `hostname` to identify the compromised endpoint.|
|10:14:33|PowerShell executed `ipconfig /all` to collect network configuration information.|
|10:14:35|PowerShell executed `net user` to enumerate local user accounts.|
|10:14:37|PowerShell executed `nltest /dclist:corp.local` to enumerate Domain Controllers.|
|10:14:31|PowerShell created `stage1.ps1` in `AppData\Local\Temp`.|
|10:14:31|`stage1.ps1` was modified immediately after creation.|
|10:14:32|PowerShell created `inventory.tmp`.|
|10:14:36|`inventory.tmp` was modified.|
|10:14:29 - 10:14:42|PowerShell established repeated outbound HTTPS connections to `198.51.100.88` (`cdn-storage-sync.com`) approximately every three seconds, consistent with beaconing behavior.|


# 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---------|-----------|----|----------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell launched by `mshta.exe`. |
| Execution | System Binary Proxy Execution: Mshta | T1218.005 | `mshta.exe` executed `Invoice_Review.hta`. |
| Discovery | Account Discovery | T1087.001 | `net user` execution. |
| Discovery | System Information Discovery | T1082 | `hostname` and `ipconfig /all`. |
| Discovery | Domain Trust Discovery | T1482 | `nltest /dclist:corp.local`. |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Repeated HTTPS communications over port 443. |

# 7. Indicators of Compromise (IOC)

## Files

| IOC | Description |
|-----------|-------------|
| Invoice_Review.hta | Initial HTA file executed by the user. |
| stage1.ps1 | Suspicious PowerShell payload created during execution. |
| inventory.tmp | Temporary file created and modified after PowerShell execution. |

---

## Processes

- mshta.exe
- powershell.exe
- cmd.exe

---

## Commands

```text
powershell.exe -nop -w hidden -enc <Base64>

whoami

hostname

ipconfig /all

net user

nltest /dclist:corp.local
```

---

## Network

| IOC | Description |
|-----------|-------------|
| 198.51.100.88 | External IP contacted repeatedly. |
| cdn-storage-sync.com | External domain contacted through HTTPS. |
| TCP/443 | Outbound HTTPS communication. |

---

## Directories

```text
C:\Users\j.smith\Downloads\
```

```text
C:\Users\j.smith\AppData\Local\Temp\
```


# 8. Investigation Phases

---

## Phase 1 – Initial Process Investigation

### Objective

Determine how the alert was triggered, identify the parent-child process relationship, and understand the initial execution chain.

### Why DeviceProcessEvents?

The alert was generated due to the execution of **mshta.exe**, making **DeviceProcessEvents** the most appropriate table to reconstruct the process tree and identify the sequence of process executions.

The objective was to determine:

- How `mshta.exe` was executed.
- Whether child processes were created.
- Whether the execution appeared legitimate or suspicious.

### KQL

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-014"
| where FileName == "mshta.exe"
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
      │
      ▼
mshta.exe
      │
      ▼
Invoice_Review.hta
      │
      ▼
powershell.exe
      │
      ▼
cmd.exe
```

The PowerShell process was executed with the following parameters:

```text
powershell.exe -nop -w hidden -enc <Base64>
```

The parameters indicated an attempt to reduce visibility and execute an encoded command.

PowerShell subsequently launched several system discovery commands, including:

- `whoami`
- `hostname`
- `ipconfig /all`
- `net user`
- `nltest /dclist:corp.local`

These commands demonstrated that the attacker was collecting information about the compromised endpoint and its environment.

### Investigation Decision

At this stage, the activity could no longer be considered a simple execution of `mshta.exe`.

The encoded PowerShell command and the execution of multiple discovery commands significantly increased the level of suspicion.

The investigation hypothesis evolved from **"suspicious process execution"** to **"possible malicious execution followed by system and account discovery."**

The next priority was to determine whether the endpoint established external communications indicative of Command and Control (C2) activity.

---

## Phase 2 – Network Investigation

### Objective

Determine whether the suspicious PowerShell activity established outbound network communications and identify potential indicators of Command and Control (C2).

The primary objective was to determine whether the endpoint communicated with external infrastructure after the execution of the encoded PowerShell command.

### Why DeviceNetworkEvents?

Following the discovery of an encoded PowerShell command and multiple system discovery commands, the next investigative question was whether the attacker attempted to communicate with an external server.

The **DeviceNetworkEvents** table records outbound and inbound network activity, making it the most appropriate source to identify external communications, suspicious domains, remote IP addresses, ports, and communication patterns.

### KQL

```kql
DeviceNetworkEvents
| where DeviceName == "FIN-WS-014"
| project DeviceName,
          Timestamp,
          RemoteIP,
          RemoteUrl,
          RemotePort,
          InitiatingProcessFileName,
          ActionType,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Findings

The investigation revealed multiple successful outbound HTTPS connections initiated by **powershell.exe**.

The endpoint repeatedly communicated with the following external infrastructure:

| Remote IP | Domain | Port |
|-----------|--------|------|
|198.51.100.88|cdn-storage-sync.com|443|

The connections occurred shortly after the execution of the encoded PowerShell command.

Analysis of the timestamps revealed a recurring communication interval of approximately **three seconds**, indicating a repetitive outbound communication pattern.

Although beaconing behavior alone does not confirm Command and Control activity, the combination of:

- Encoded PowerShell execution
- System discovery commands
- Repeated outbound HTTPS connections
- Consistent communication intervals

significantly increased the likelihood of malicious activity.

### Investigation Decision

At this stage, the investigation hypothesis evolved from **possible malicious execution** to **suspected multi-stage malware activity with potential Command and Control (C2) communications**.

The incident severity was increased from **Medium** to **High**, as the available evidence suggested that the attacker had progressed beyond local reconnaissance and had established external communications.

The next investigation focused on file activity to determine whether additional payloads or temporary artifacts had been created during the attack.

---

## Phase 3 – File Investigation

### Objective

Identify whether additional files were created or modified after the execution of the malicious HTA file and determine whether new payloads were deployed during the attack.

### Why DeviceFileEvents?

After confirming suspicious process execution and repeated outbound network communications, the next investigative step was to determine whether PowerShell created or modified additional files on the endpoint.

The **DeviceFileEvents** table records file creation, modification, deletion, and movement events, allowing investigators to identify payload deployment and temporary artifacts generated during an attack.

### KQL

```kql
DeviceFileEvents
| where DeviceName == "FIN-WS-014"
| where Timestamp between (datetime(2026-07-18 10:14:20) .. datetime(2026-07-18 10:15:00))
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

The investigation identified multiple file operations immediately after the execution of the encoded PowerShell command.

The following files were observed:

| File | Action |
|------|--------|
|Invoice_Review.hta|Created|
|stage1.ps1|Created and Modified|
|inventory.tmp|Created and Modified|

The PowerShell process created **stage1.ps1** and **inventory.tmp** inside:

```text
C:\Users\j.smith\AppData\Local\Temp\
```

The creation and immediate modification of these files suggested that PowerShell generated additional artifacts after the initial execution.

Although the content of the files was not available through the collected telemetry, **stage1.ps1** was assessed as a likely intermediate PowerShell payload used during the attack.

The use of the **AppData\Local\Temp** directory was also considered suspicious because attackers frequently use temporary folders to stage payloads without requiring administrative privileges.

### Investigation Decision

The investigation confirmed that the attack progressed beyond the initial HTA execution.

Additional payloads were deployed after PowerShell execution, strengthening the hypothesis of a multi-stage attack involving payload staging and external communications.

At this point, sufficient evidence existed to classify the incident as **High Severity** and initiate containment procedures while continuing to assess the overall scope of the compromise.

---

## Phase 4 – Threat Hunting

### Objective

Determine whether the malicious activity observed on **FIN-WS-014** affected additional endpoints or users within the environment.

### Why Threat Hunting?

Once malicious activity was confirmed, it was necessary to determine the scope of the compromise.

Threat Hunting focused on identifying similar indicators across the environment to determine whether additional systems had executed the same payloads or communicated with the same external infrastructure.

---

### Hunting Question 1

**Did any other endpoint execute mshta.exe?**

```kql
DeviceProcessEvents
| where FileName == "mshta.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine
```

**Result**

No additional suspicious executions were identified during the investigation period.

---

### Hunting Question 2

**Did other devices execute the HTA file?**

```kql
DeviceFileEvents
| where FileName == "Invoice_Review.hta"
| project Timestamp,
          DeviceName,
          FolderPath,
          ActionType
```

**Result**

The HTA file was only observed on **FIN-WS-014**.

---

### Hunting Question 3

**Was stage1.ps1 executed on additional endpoints?**

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "stage1.ps1"
| project Timestamp,
          DeviceName,
          ProcessCommandLine
```

**Result**

No additional executions were identified.

---

### Hunting Question 4

**Did other endpoints communicate with the same external IP address?**

```kql
DeviceNetworkEvents
| where RemoteIP == "198.51.100.88"
| project Timestamp,
          DeviceName,
          RemoteIP,
          RemotePort
```

**Result**

No additional endpoints communicated with the identified external IP.

---

### Hunting Question 5

**Were there other PowerShell executions using Base64-encoded commands?**

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-enc"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine
```

**Result**

No additional suspicious encoded PowerShell executions were identified.

---

### Final Hunting Assessment

Based on the available telemetry, the compromise appeared to be limited to **FIN-WS-014**.

No evidence of additional compromised endpoints or widespread malicious activity was identified during the investigation.


# 9. Containment Actions

- Escalate the incident to the SOC Level 2 team for advanced investigation.
- Isolate the affected endpoint from the network.
- Block outbound communications to the identified malicious IP address and domain.
- Terminate malicious PowerShell processes if still active.
- Preserve forensic evidence before performing remediation.
- Reset the affected user's credentials if compromise is confirmed.
- Monitor the environment for additional executions of `mshta.exe` and encoded PowerShell commands.

# 10. Detection Opportunities

- Generate alerts when `mshta.exe` launches PowerShell.
- Detect PowerShell executions using the `-enc`, `-nop`, or `-w hidden` parameters.
- Monitor repeated outbound HTTPS connections exhibiting beaconing behavior.
- Alert when PowerShell creates executable content inside `AppData\Local\Temp`.
- Detect execution of HTA files from user directories such as `Downloads`.
- Monitor repeated executions of system discovery commands immediately after PowerShell execution.

# 11. Lessons Learned

- Legitimate Windows binaries such as `mshta.exe` can be abused to execute malicious payloads.
- Encoded PowerShell commands should always be investigated in context rather than treated as inherently malicious.
- Discovery commands often represent an early stage of post-exploitation activity.
- Repeated outbound HTTPS connections may indicate beaconing behavior and should be correlated with process execution.
- Temporary directories such as `AppData\Local\Temp` are common locations for staging malicious payloads.
- Effective investigations require correlating process, file, and network telemetry rather than relying on a single data source.

