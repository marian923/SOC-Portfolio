# MOVEit 2023

## Executive Summary
This investigation reconstructs the exploitation of the MOVEit Transfer vulnerability (CVE-2023-34362) based on publicly available information and observed attack patterns. The activity is consistent with the exploitation of a public-facing application that allowed an attacker to gain unauthorized access to the MOVEit environment.
Following the exploitation of the vulnerable application, a suspicious ASPX file was created within the web directory, enabling command execution through the IIS web server. The attacker subsequently launched PowerShell, accessed sensitive data stored in HR and Payroll directories, created a compressed archive, and transferred the collected data to an external destination.
The sequence of events indicates a successful compromise of the MOVEit Transfer application followed by data collection, archive creation, exfiltration, and the establishment of persistence through a scheduled task.



## Incident Overview

### Attack Type
Exploitation of a Public-Facing Application, Web Shell Activity, Command Execution, Data Collection, Data Exfiltration, and Persistence.

### Date
May 2023

### Objective
The attackers sought to exploit a vulnerability in the MOVEit Transfer application to gain unauthorized access, collect sensitive information, and exfiltrate data from the affected environment.

### Technologies Involved
* MOVEit Transfer
* Microsoft IIS
* ASPX Web Applications
* PowerShell
* Windows Command Prompt (CMD)
* Scheduled Tasks
* Firewall Logs
* File Servers
* Network Monitoring Systems



### Case Context
This investigation is a reconstruction of the MOVEit Transfer compromise associated with CVE-2023-34362. Public reporting indicates that attackers exploited a vulnerability in the MOVEit application to upload malicious files, execute commands on the server, access sensitive information, and exfiltrate data.
This reconstruction was developed for educational and cybersecurity analysis purposes and does not represent the complete internal investigation of affected organizations.


## Attack Flow Diagram
```text
Exploit Public-Facing Application
        ↓
human2.aspx Created
        ↓
Web Shell Execution
        ↓
w3wp.exe → cmd.exe
        ↓
cmd.exe → powershell.exe
        ↓
HR Data Access
        ↓
Payroll Data Access
        ↓
Archive Creation (ZIP)
        ↓
Outbound Transfer
        ↓
Persistence (Scheduled Task)
```

## Key Log Evidence

```text
Web Server Log
POST /moveitisapi/moveitisapi.dll
Source IP:45.88.120.33
Response:200 OK
```

```text
IIS Log
File Created
Path:
C:\MOVEitTransfer\wwwroot\human2.aspx
```

```text
IIS Worker Process
w3wp.exe
Child Process:cmd.exe
```

```text
Process Creation
Parent:cmd.exe
Child:powershell.exe
Command:powershell.exe -ExecutionPolicy Bypass
```

```text
File Server
Large Number Of Files Accessed
Directory:Payroll
```

```text
Archive Created
Name:employees_2023.zip
Size:2.3 GB
```

```text
Network Monitoring
Outbound Transfer
Destination:185.199.110.23
Volume:2.3 GB
```



## Timeline of Events

| Time | Event |
|------------|------------|
| 02:11 | The attacker sent multiple GET and POST requests to the MOVEit application, including requests to guestaccess.aspx and moveitisapi.dll. |
| 02:11 | A suspicious file named human2.aspx was created within the MOVEit web directory.  |
| 02:11 | The IIS worker process (w3wp.exe) launched cmd.exe, indicating possible command execution through a web shell. |
| 02:11 | PowerShell was executed using the ExecutionPolicy Bypass parameter, allowing scripts to run without standard restrictions. |
| 02:13 | The attacker accessed sensitive files located in the HR and Payroll directories. |
| 02:15 | The collected data was compressed into an archive named employees_2023.zip. |
| 02:16 | An outbound connection was established and a large volume of data was transferred to an external IP address, indicating possible data exfiltration.  |
| 02:18 | A scheduled task named HealthCheckUpdate was created, potentially establishing persistence on the system. |


## Indicators of Compromise (IOCs)

### Source IP Addresses:
* 45.88.120.33
* 10.10.20.15

### Destination IP Addresses
* 185.199.110.23

### Suspicious Files
* C:\MOVEitTransfer\wwwroot\human2.aspx
* employees_2023.zip

### Processes:
* w3wp.exe
* cmd.exe
* powershell.exe

### Observed Activities:
* Web Shell Creation
* PowerShell ExecutionPolicy Bypass
* Archive Creation
* Data Exfiltration
* Scheduled Task Creation


## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|------------|
| Exploit Public-Facing Application   | T1190  |
| Server Software Component: Web Shell  | T1505.003  |
| Command and Scripting Interpreter: PowerShell  | T1059.001  |
| Scheduled Task  | T1053.005 |
| Archive Collected Data | T1560.001  |
| Data from Information Repositories | T1213 |
| Exfiltration Over Web Services | T1567 |

## Severity Assessment
Severity: Critical
### Justification
This incident was classified as Critical due to the successful exploitation of a public-facing application, the creation of a web shell, execution of PowerShell commands, access to sensitive HR and Payroll data, archive creation, and confirmed outbound data transfer.
The compromise allowed the attacker to gain unauthorized access to sensitive information and exfiltrate data outside the organization. The exposure of employee and payroll information significantly increased the business, operational, and security impact of the incident.



## Detection Opportunities 
* Public-Facing Application Monitoring
Monitor web applications for unusual HTTP requests, unexpected POST activity, and exploitation attempts targeting known vulnerabilities.
* Web Shell Detection
Generate alerts when new ASPX files are created within web application directories.
* IIS Process Monitoring
Investigate instances where w3wp.exe launches command-line interpreters such as cmd.exe or powershell.exe.
* PowerShell Abuse Detection
Alert on PowerShell executions using ExecutionPolicy Bypass or other suspicious execution parameters.
* Sensitive Data Access Monitoring
Identify abnormal access to HR, Payroll, Finance, or other high-value repositories.
* Archive Creation Detection
Monitor the creation of large ZIP or archive files containing business-sensitive information.
* Data Exfiltration Monitoring
Generate alerts for large outbound data transfers to external destinations, particularly when preceded by archive creation.
* Persistence Monitoring
Investigate newly created scheduled tasks, especially those created shortly after suspicious web activity.



## Containment Actions
*  Isolate the affected MOVEit server from the network.
* Remove the malicious file (human2.aspx).
* Disable malicious scheduled tasks.
* Review IIS logs and web server activity.
* Reset credentials potentially exposed during the incident.
* Investigate accessed HR and Payroll files.
* Block malicious IP addresses involved in the attack.
* Validate that no additional web shells remain on the server.
* Escalate the incident to the Incident Response team.


## Lessons Learned
* Public-facing applications should be patched promptly to reduce exposure to known vulnerabilities.
* Web server logs should be continuously monitored for suspicious file creation and command execution activity.
* Unexpected child processes launched by IIS (w3wp.exe → cmd.exe → powershell.exe) should be treated as high-priority alerts.
* Organizations should monitor large archive creation and outbound data transfers.
* Regular vulnerability management and patching programs are essential for reducing attack surface.
* Web shell detection capabilities should be implemented and regularly tested.


## Sources
This investigation is a reconstruction based on publicly available information regarding the MoveIt 2023 cyberattack and does not represent internal MoveIt incident data.