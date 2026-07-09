# Uber_2022_Attack_Reconstruction

## Executive Summary
This investigation reconstructs the Uber 2022 security breach based on publicly available information and observed attack patterns. The activity is consistent with an identity-focused attack in which valid credentials were used to initiate repeated authentication attempts against a corporate account.
Following multiple failed login attempts, a series of MFA push notifications were sent to the targeted user. After an MFA approval was obtained, the attacker successfully accessed the corporate environment through the VPN. Subsequent activity included access to a Password Vault, viewing of sensitive credentials, use of privileged accounts, privilege escalation activity, and signs of lateral movement across internal systems.
The sequence of events indicates a compromise of corporate identity controls followed by unauthorized access to privileged resources and expansion of access within the environment.

## Incident Overview

### Attack Type
Identity Compromise, MFA Fatigue, Privilege Escalation, Credential Access, and Lateral Movement.

### Date
September 2022

### Objective
The objective of the attackers was to gain unauthorized access to the corporate environment by abusing valid credentials and authentication mechanisms. After obtaining access, the attackers sought privileged credentials, escalated their permissions, and expanded their access to additional systems within the organization.

### Technologies Involved
* Identity Platform
* VPN Gateway
* Multi-Factor Authentication (MFA)
* Password Vault
* Endpoint Detection and Response (EDR)
* Windows Systems
* SMB (Server Message Block)
* Firewall Logs
* Internal Corporate Chat

### Case Context
This investigation is a reconstruction of the Uber 2022 breach based on publicly available information. Public reports indicate that the attacker obtained valid credentials belonging to a contractor and used an MFA fatigue technique to gain access to the corporate environment. After gaining access, the attacker leveraged internal resources, accessed privileged credentials, and expanded access across multiple systems.
This reconstruction was developed for educational and cybersecurity analysis purposes and does not represent the complete internal Uber incident data.



## Attack Flow Diagram
```text
Compromised Contractor Credentials
        ↓
Repeated MFA Push Requests
        ↓
MFA Approval
        ↓
VPN Access
        ↓
Internal Chat Access
        ↓
Password Vault Access
        ↓
Admin Credential Discovery
        ↓
Privilege Escalation
        ↓
Lateral Movement
        ↓
Access to Critical Systems 
```

## Key Log Evidence

```text
VPN Failed Login
User: external.contractor
Source IP: 185.77.90.21
```

```text
MFA Push Approved
User:external.contractor
```

```text
VPN Login Success
User:external.contractor
Source IP: 185.77.90.21
```

```text
Password Vault
Sensitive Credentials Viewed
User:external.contractor
```

```text
EDR Alert
Privilege Escalation Activity
Hostname: ADMIN-WS01
```

```text
EDR Alert
Possible Lateral Movement
Multiple Hosts
```

## Timeline of Events

| Time | Event |
|------------|------------|
| 08:12 | Multiple failed login attempts were observed for the account external.contractor. |
| 08:14 | Multiple MFA push notifications were sent to the user.  |
| 08:14 | An MFA push notification was approved.  |
| 08:15 | A successful VPN login was observed from an external IP address. |
| 08:18 | The account external.contractor posted a message in an internal chat channel requesting information about administrative credentials. |
| 08:21 | The account external.contractor gained access to the Password Vault.  |
| 08:22 | Sensitive credentials were viewed within the Password Vault.  |
| 08:23 | A successful login was observed using the account admin.ops. |
| 08:24 | The EDR generated an alert indicating privilege escalation activity.  |
| 08:25 | Multiple SMB connections were observed between internal systems. |
| 08:26 | The EDR detected possible lateral movement across multiple hosts. |

## Indicators of Compromise (IOCs)

### Accounts:
* external.contractor
* admin.ops
### Source IP Addresses:
* 185.77.90.21
* 10.22.15.40
### Destination Hosts:
* 10.22.15.22
* 10.22.15.33
### Observed Activities:
* MFA Fatigue
* Password Vault Access
* Sensitive Credential Exposure
* Privilege Escalation
* SMB Activity
* Possible Lateral Movement

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID |
|------------|------------|
| Valid Accounts | T1078 |
| Valid Accounts: Local Accounts | T1078.003  |
| Multi-Factor Authentication Request Generation | T1621  |
| Abuse Elevation Control Mechanism | T1548 |
| SMB/Windows Admin Shares | T1021.002  |
| Data from Local System | T1005 |

## Severity Assessment
Severity: High
### Justification
* Identity compromise.
* Successful VPN access.
* Access to Password Vault.
* Credential Exposure.
* Privilege Escalation Activity.
* Possible Lateral Movement.

## Detection Opportunities
* MFA Fatigue Detection
Generate alerts when multiple MFA push notifications are sent within a short time period to the same user.
* Unusual Authentication Patterns
Detect repeated login attempts followed by a successful authentication from the same source.
* Password Vault Monitoring
Monitor access to password management systems and generate alerts when privileged credentials are viewed or exported.
* Privileged Account Usage
Identify when administrative accounts are accessed from unusual locations, devices, or user contexts.
* Internal Reconnaissance Activity
Detect searches, enumeration, or unusual access patterns within internal collaboration platforms.
* Privilege Escalation Monitoring
Generate alerts when accounts gain elevated privileges shortly after authentication events.
* Lateral Movement Detection
Monitor remote administration protocols and authentication activity across multiple systems.



## Containment Actions
* Disable compromised accounts.
* Revoke active sessions and VPN access.
* Block the suspicious external IP address.
* Reset exposed credentials stored in the Password Vault.
* Investigate the use of privileged accounts.
* Review VPN access logs and MFA activity.
* Escalate the incident to the Incident Response team.

## Lessons Learned
* Implement protections against MFA fatigue attacks.
* Strengthen user awareness training regarding authentication requests.
* Apply the Principle of Least Privilege to reduce the impact of credential compromise.
* Monitor access to privileged credential repositories such as Password Vaults.
* Correlate VPN, identity, EDR, and authentication logs to detect identity-based attacks more quickly.


## Sources
This investigation is a reconstruction based on publicly available information regarding the Uber Data Breach 2022 cyberattack and does not represent internal Uber incident data.