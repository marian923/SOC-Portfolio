# SOLARWINDS SUPPLY CHAIN ATTACK 2020

## Executive Summary
The SolarWinds supply chain attack is one of the most significant cybersecurity incidents in recent history. The attackers compromised the SolarWinds Orion software build process and inserted malicious code into legitimate software updates distributed to customers.
The malware monitored the build environment, modified source code files before compilation, and allowed a malicious DLL to be generated and digitally signed as part of a legitimate software release. The attack leveraged trusted software distribution mechanisms, making detection extremely difficult and enabling access to numerous organizations worldwide.
This investigation focuses on the suspicious processes, persistence mechanisms, source code modifications, and command execution activities associated with the SUNSPOT malware used during the compromise.


## Incident Overview

### Attack Type
Supply Chain Attack, Persistence, Source Code Manipulation, Living Off The Land (LOLBins), and Command and Control Activity.

### Date
March 2020

### Objective
The attackers sought to compromise the SolarWinds Orion software build environment and insert malicious code into legitimate software updates. By tampering with the build process, the attackers were able to distribute malware through trusted software releases to multiple organizations.

### Technologies Involved
* SolarWinds Orion 
* MsBuild 
* Windows Scheduled Tasks 
* PowerShell 
* Command Prompt (CMD) 
* DNS Communications 
* Windows Services 
* Build Servers 
* Firewall Logs 
* Endpoint Detection and Response (EDR) 


### Case Context
This investigation is a reconstruction of the SolarWinds supply chain attack based on publicly available information and technical reports. The attack involved the SUNSPOT malware, which monitored the SolarWinds build environment and modified source code files before compilation. The resulting software updates contained malicious code while appearing legitimate and digitally signed.
This reconstruction was developed for educational and cybersecurity analysis purposes and does not represent the complete internal SolarWinds investigation.


## Attack Flow Diagram
```text
taskhostsvc.exe Created
        ↓
Scheduled Task Persistence
        ↓
vmware-vmdmp.log Creation
        ↓
Monitor MsBuild.exe
        ↓
Source Code Modification
        ↓
Build Process Triggered
        ↓
Malicious DLL Generated
        ↓
DNS Communication
        ↓
PowerShell Execution
        ↓
Compromised Software Update Distribution
```

## Key Log Evidence

```text
Scheduled Task Created
TaskName=TaskHostSvc
Trigger=At system startup
Action=C:\Windows\System32\taskhostsvc.exe
```

```text
Process Access
SourceProcess=taskhostsvc.exe
TargetProcess=MsBuild.exe
AccessType=ReadProcessMemory
```

```text
File Modified
Process=taskhostsvc.exe
Path=C:\Build\Orion\SolarWinds.Orion.Core.BusinessLayer\InventoryManagers
```

```text
DNS Query
Query=avsvmcloud.com
```

```text
Process=powershell.exe
CommandLine=powershell.exe -ExecutionPolicy Bypass
```



## Timeline of Events

| Time | Event |
|------------|------------|
| 11:40 | A suspicious executable named taskhostsvc.exe was created on the build server. |
| 11:41 | A scheduled task was created to execute taskhostsvc.exe at system startup.  |
| 09:12 | The process taskhostsvc.exe was executed and established persistence within the system.  |
| 09:12 | A log file named vmware-vmdmp.log was created in the Windows temporary directory. |
| 09:13 | The process obtained elevated privileges, including SeDebugPrivilege. |
| 09:15 | The process monitored MsBuild.exe and accessed its memory.  |
| 09:16 | The SolarWinds Orion project files were accessed.  |
| 09:17 | Source code files were modified prior to compilation. |
| 09:18 | The SolarWinds Orion project was successfully compiled by MsBuild.exe.  |
| 09:19 | A signed DLL was generated as part of the build process. |
| 09:22 | Suspicious DNS queries and outbound network communications were observed. |
| 09:25 | The process executed reconnaissance commands, including whoami. |
| 09:26 | PowerShell was executed using the ExecutionPolicy Bypass parameter. |

## Indicators of Compromise (IOCs)

### Domains:
* avsvmcloud.com
### Source IP Addresses:
* 87.251.67.14
### Processes:
* taskhostsvc.exe
* MsBuild.exe
* cmd.exe
* powershell.exe
### Observed Activities:
* Scheduled Task Creation
* Source Code Modification
* Privilege Escalation
* PowerShell ExecutionPolicy Bypass
* Suspicious DNS Activity

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|------------|
| Scheduled Task  | T1053.005 |
| Masquerading  | T1036 |
| Process Discovery  | T1057 |
| Command and Scripting Interpreter: PowerShell  | T1059.001  |
| Data Manipulation Stored - Data Manipulation | T1565.001  |
| Boot or Logon Autostart Execution | T1547 |

## Severity Assessment
Severity: Critical
### Justification
This incident was classified as Critical due to the compromise of the SolarWinds Orion software build environment and the modification of source code prior to compilation.
The attacker established persistence through a scheduled task, monitored the build process, modified source code files, and enabled the creation of a malicious software component that appeared legitimate and digitally signed. This activity affected the integrity of the software supply chain and created the potential for widespread compromise across multiple organizations.
Additional factors supporting the Critical severity rating include:
* Persistence through Scheduled Tasks. 
* Source Code Manipulation. 
* Abuse of Legitimate Build Processes. 
* Suspicious DNS Communications. 
* PowerShell Execution with ExecutionPolicy Bypass. 
* Potential Command and Control Activity. 
* Large-scale downstream impact through trusted software distribution. 
The compromise extended beyond a single host and introduced risk to numerous organizations that relied on SolarWinds Orion updates, significantly increasing the overall business and security impact.


## Detection Opportunities 
* Build Environment Monitoring
Monitor build servers for the creation of unexpected executables, services, or scheduled tasks.
* Scheduled Task Analysis
Investigate scheduled tasks created outside approved software deployment or administrative procedures.
* Process Access Monitoring
Detect processes attempting to read the memory of build-related applications such as MsBuild.exe.
* Source Code Integrity Monitoring
Generate alerts when source code files are modified immediately before software compilation.
* Suspicious Build Artifacts
Monitor the creation of DLLs and build outputs that differ from expected baselines.
* DNS and Network Monitoring
Identify unusual DNS requests and outbound connections originating from build infrastructure.
* PowerShell Detection
Alert on PowerShell executions using parameters such as ExecutionPolicy Bypass, especially on build servers.
* Parent-Child Process Analysis
Investigate suspicious process chains involving build tools, command shells, and PowerShell execution.



## Containment Actions
* Identify affected build servers
* Disable malicious scheduled tasks
* Isolate compromised systems
* Review source code integrity
* Validate software artifacts
* Remove malicious binaries


## Lessons Learned
* Build environments should be continuously monitored for unauthorized file modifications.
* Software supply chain security is critical for protecting customers and downstream organizations.
* Scheduled tasks and unexpected privileged processes should be investigated promptly.
* Source code integrity validation should be implemented throughout the development lifecycle.
* Organizations should monitor unusual interactions with build tools such as MsBuild.exe.



## Sources
This investigation is a reconstruction based on publicly available information regarding the SolarWinds 2020 cyberattack and does not represent internal SolarWinds incident data.