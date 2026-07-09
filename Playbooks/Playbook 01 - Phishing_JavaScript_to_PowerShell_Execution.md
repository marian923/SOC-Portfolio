# Playbook 01 - Phishing JavaScript to PowerShell Execution

# Executive Summary

A phishing email led to the execution of a JavaScript file through **wscript.exe**. The script launched **PowerShell**, downloaded a second payload from an external server, and executed it on the endpoint. Based on the observed process chain and network activity, the incident was classified as **High Severity**. The endpoint should be isolated, the indicators blocked, and additional threat hunting performed to identify any other affected systems.
# Objective

This playbook explains how to investigate a phishing attack where a user opens a malicious email attachment that executes a JavaScript file, launches PowerShell, downloads another payload, and executes it on the endpoint.

---

# Scenario

A user from the Human Resources department reported that the computer became slow after opening an email attachment called **"Benefits Update"**.

The investigation showed that the attachment executed a JavaScript file using **wscript.exe**, which later launched **PowerShell** to download and run another payload.

---

# Attack Flow Diagram

```text
Phishing Email
        │
        ▼
Outlook
        │
        ▼
Benefits_Update.js
        │
        ▼
wscript.exe
        │
        ▼
powershell.exe
        │
        ▼
Download payload.ps1
        │
        ▼
Execute payload.ps1
```

---

# Timeline

| Time     | Event                                                                  |
| -------- | ---------------------------------------------------------------------- |
| 14:07:58 | The user opened the phishing email attachment from Outlook.            |
| 14:07:58 | Outlook started **wscript.exe**.                                       |
| 14:07:58 | **Benefits_Update.js** was executed from the Temp folder.              |
| 14:08:02 | The JavaScript file was executed again through **cmd.exe**.            |
| 14:08:04 | **wscript.exe** launched **PowerShell**.                               |
| 14:08:04 | PowerShell downloaded **payload.ps1** from an external server.         |
| 14:08:09 | PowerShell executed **payload.ps1** using **ExecutionPolicy Bypass**.  |
| 14:08:10 | The user noticed that the computer became slow and reported the issue. |

---
# MITRE ATT&CK Mapping

| Tactic         | Technique                      |
| -------------- | ------------------------------ |
| Initial Access | T1566.002 - Spearphishing Link |
| Execution      | T1059.007 - JavaScript         |
| Execution      | T1059.001 - PowerShell         |
---

# Indicators of Compromise (IOC)

## IP Address

* 203.0.113.25

## Files

* Benefits_Update.js
* payload.ps1

## Processes

* wscript.exe
* powershell.exe
* cmd.exe

## Commands

* ExecutionPolicy Bypass
* Invoke-WebRequest

## Folder

```text
C:\Users\lmendez\AppData\Local\Temp\
```

---



# Investigation Steps

## Step 1 - Review running processes

### Table

DeviceProcessEvents

### Query

```kql
DeviceProcessEvents
| where DeviceName == "HR-PC-22"
| summarize count() by FileName
| top 10 by count_
```

### Purpose

Identify the most common processes running on the endpoint.

### Result

The investigation found unusual processes such as **wscript.exe**, **cmd.exe**, and **rundll32.exe**.

---

## Step 2 - Investigate wscript.exe

### Table

DeviceProcessEvents

### Query

```kql
DeviceProcessEvents
| where DeviceName == "HR-PC-22"
| where FileName == "wscript.exe"
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```

### Purpose

Understand how the script was executed.

### Result

The process was started by Outlook and executed the file **Benefits_Update.js** from the user's Temp folder.

---

## Step 3 - Review child processes

### Table

DeviceProcessEvents

### Query

```kql
DeviceProcessEvents
| where DeviceName == "HR-PC-22"
| where InitiatingProcessFileName == "wscript.exe"
| project Timestamp, FileName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```

### Purpose

Check if the script launched additional processes.

### Result

The script started **PowerShell**, which downloaded and executed another payload.

---

## Step 4 - Review file activity

### Table

DeviceFileEvents

### Query

```kql
DeviceFileEvents
| where DeviceName == "HR-PC-22"
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

### Purpose

Identify files created or modified after the PowerShell execution.

---

## Step 5 - Review network activity

### Table

DeviceNetworkEvents

### Query

```kql
DeviceNetworkEvents
| where DeviceName == "HR-PC-22"
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp asc
```

### Purpose

Identify outbound connections to external servers.

### Result

PowerShell connected to an external IP address to download the payload.

---

# Containment Actions

* Isolate the affected endpoint.
* Escalate the incident to the Incident Response team.
* Block the identified IP address and any related indicators.
* Search for the same indicators on other endpoints.
* Review if other users received the same phishing email.
* Document the investigation.

---

# Threat Hunting

Search the environment for:

* Other executions of **Benefits_Update.js**
* Other executions of **wscript.exe**
* PowerShell with **ExecutionPolicy Bypass**
* PowerShell using **Invoke-WebRequest**
* Connections to **203.0.113.25**
* Other endpoints running **payload.ps1**

---

# Detection Opportunities

* Alert when **Outlook** starts **wscript.exe**.
* Alert when **wscript.exe** launches **PowerShell**.
* Detect **ExecutionPolicy Bypass**.
* Detect **Invoke-WebRequest** downloading external files.
* Monitor JavaScript files executed from the Temp folder.


---

# Lessons Learned

* Always verify email attachments before opening them.
* Be careful with files using **.js** extensions.
* Monitor PowerShell executions with suspicious parameters.
* Detect Office applications launching scripting tools.
* User awareness training can help reduce phishing attacks.
