# MGM Resorts 2023 Incident Analysis

## Executive Summary
This investigation reconstructs the MGM Resorts 2023 cyberattack based on publicly available information. The observed activity is consistent with a social engineering (vishing) attack targeting the Help Desk, where an MFA reset was requested for a corporate account. Shortly after, successful access to identity services and the corporate VPN was observed using the compromised account.
After gaining access to the corporate environment, a new privileged account was created and added to the Domain Admins group. Additional activity related to credential dumping was detected on a Domain Controller. Finally, multiple SMB connections were observed between internal systems, followed by EDR alerts indicating potential lateral movement across the network.
The sequence of events suggests an identity compromise followed by privilege escalation and lateral movement within the corporate environment.

## Incident Overview

### Attack Type
Social Engineering (Vishing), Identity Compromise, Privilege Escalation, Credential Access, and Lateral Movement.

### Date
September 2023

### Objective
The objective of the attackers was to gain unauthorized access to the MGM Resorts corporate environment by abusing identity management processes. After obtaining access, the attackers established persistence, escalated privileges, and expanded their access across multiple systems within the network.

### Technologies Involved
* Help Desk
* Okta Identity Platform
* Multi-Factor Authentication (MFA)
* VPN Gateway
* Active Directory
* Domain Controllers
* Endpoint Detection and Response (EDR)
* Windows Systems
* SMB (Server Message Block)
* Firewall Logs

### Case Context
This investigation is a reconstruction of the MGM Resorts 2023 cyberattack based on publicly available information. According to public reports, the attackers used social engineering techniques to convince the Help Desk to reset MFA for a legitimate user account. After obtaining access, they leveraged valid credentials, created privileged accounts, performed credential dumping activities, and moved laterally across the environment.
This reconstruction was developed for educational and cybersecurity analysis purposes and does not represent the complete internal MGM Resorts incident data.


## Attack Flow Diagram
```text
Help Desk Call (Vishing)
        ↓
MFA Reset
        ↓
Valid Account Access
        ↓
VPN Login
        ↓
Active Directory Access
        ↓
Create New Account (svc_backup2)
        ↓
Add to Domain Admins
        ↓
Credential Dumping
        ↓
SMB Activity
        ↓
Lateral Movement
        ↓
Ransomware 
```

## Key Log Evidence

```text
HelpDesk Ticket
Caller:John Smith
Department:Finance
Request:MFA reset
```

```text
Okta
MFA Reset Completed
User:john.smith
Performed By:HelpDesk01
Reason:New phone
```

```text
Okta
Login Success
User:john.smith
Source IP:185.244.25.19
Country:Unknown
```

```text
Domain Controller
EventID=4720
User Account Created
Account:svc_backup2
```

```text
Domain Controller
Account Added To Group
Account:svc_backup2
Group: Domain Admins
```

```text
EDR Alert
Hostname:DC-01
Alert:Credential Dumping Activity
```

```text
Windows Event
EventID=7045
Service Installed
Name:RemoteUpdateService
```

```text
EDR Alert
Multiple Hosts
Alert:Lateral Movement Suspected
```
## Timeline of Events

| Time | Event |
|------------|------------|
| 15:21 | A request to reset MFA for the account john.smith was received through the Help Desk. |
| 15:25 | The Help Desk completed the MFA reset for the account john.smith.  |
| 15:28 | A successful login for the account john.smith was observed from an external IP address.  |
| 15:29 | The account john.smith established a successful VPN connection to the corporate network. |
| 15:31 | Successful Active Directory authentication was recorded using the account john.smith.|
| 15:35 | A new account named svc_backup2 was created.  |
| 15:36 | The account svc_backup2 was added to the Domain Admins group.  |
| 15:38 | The EDR detected activity consistent with credential dumping on a Domain Controller. |
| 15:39 | Multiple SMB connections to internal systems were observed.  |
| 15:43 | The EDR generated an alert indicating possible lateral movement across multiple hosts. |

## Indicators of Compromise (IOCs)

### Accounts:
* john.smith
* svc_backup2
### Source IP Addresses:
* 185.244.25.19
* 10.10.50.20
### Destination Hosts:
* 10.10.60.15
* 10.10.60.22
* 10.10.60.31
### Suspicious Services:
* RemoteUpdateService
### Observed Activities:
* MFA Reset
* VPN Login
* Creation of Privileged Account
* Credential Dumping Activity
* SMB Connections
* Lateral Movement Alert

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|------------|
| Valid Accounts | T1078 |
| Valid Accounts: Local Accounts | T1078.003  |
| Account Manipulation: Additional Local or Domain Groups | T1098.007  |
| Modify Authentication Process | T1556 |

## Severity Assessment
Severity: High
### Justification
* Identity compromise.
* Successful VPN access.
* Creation of a privileged account.
* Credential dumping activity.
* Lateral movement indicators.

## Detection Opportunities
* MFA Reset Monitoring
Generate alerts when MFA reset requests are performed through the Help Desk, especially for privileged or high-value accounts.
* VPN Access Following MFA Reset
Correlate MFA reset events with successful VPN logins occurring shortly afterward.
* New Account Creation
Monitor Event ID 4720 and investigate newly created accounts, particularly those created outside normal administrative procedures.
* Privileged Group Modifications
Alert on additions to sensitive groups such as Domain Admins, Enterprise Admins, or Backup Operators.
* Credential Dumping Detection
Monitor for suspicious access to LSASS memory, credential dumping tools, or EDR alerts associated with credential theft.
* SMB-Based Lateral Movement
Detect unusual SMB connections between hosts, especially when initiated by newly created or recently elevated accounts.
* Service Installation Monitoring
Monitor Event ID 7045 for new service creation, particularly services with unusual names or execution paths.

## Containment Actions
* Disable compromised accounts.
* Revoke active sessions and VPN access.
* Review privileged group memberships.
* Investigate credential dumping activity.
* Isolate affected systems if malicious activity is confirmed.
* Escalate the incident to the Incident Response team.

## Lessons Learned
* Strengthen Help Desk identity verification procedures.
* Improve validation processes for MFA reset requests.
* Monitor the creation of privileged accounts and group membership changes.
* Treat credential dumping alerts on Domain Controllers as high-priority events.
* Correlate identity, firewall, EDR, VPN, and Active Directory logs to improve incident detection and response.

## Sources
This investigation is a reconstruction based on publicly available information regarding the MGM Resorts 2023 cyberattack and does not represent internal MGM incident data.