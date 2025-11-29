# 🛡️ Incident Response - **PowerShell Suspicious Web Request**

## 📌 Executive Summary
A custom Threat Analytics rule was created and enabled in Microsoft Sentinel to detect brute-force login attempts on the devices in the organisation. The rule trigered an Incident, detecting brute-force attempt on 2 devices by 2 RemoteIPs. Investigation revealed **13 RemoteIPs targetting 3 Devices** with highest number of attempts as 178. The incident was confirmed as a **true positive**, but **no successful logons occurred**. Affected devices were isolated, scanned, and protected through updated network controls.

**Followed NIST 800-61 Incident Response LifeCycle**

### 🧰 Tools Used

- **Microsoft Sentinel** – Custom analytics rule creation and incident investigation  
- **KQL (Kusto Query Language)** – Threat hunting and brute-force correlation  
- **Microsoft Defender for Endpoint (MDE)** – Device isolation, AV scans, and investigation packages  
- **Azure Network Security Groups (NSG)** – Restricting external access  
- **DeviceLogonEvents** – Primary log source for authentication activity

---

## Table of Contents

- [Preparation: Alert rule to detect Brute-force attack](https://github.com/sunilselvaraj1/Brute-Force-Attack/blob/main/README.md#%EF%B8%8F-1-preparation-alert-rule-to-detect-brute-force-attack)
- [Detection & Analysis](https://github.com/sunilselvaraj1/Brute-Force-Attack#-2-detection--analysis)
     - [Alert Triggered](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#21-alert-trigger)
     - [Initial Validation](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#22-initial-validation)
     - [Investigate to find all attacking IPs](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#22-initial-investigation)
     - [Investigate to find additional impacted devices](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#23-identifying-additional-impacted-devices)
     - [Check for successful login attempt](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#34-checking-for-successful-logins)
- [Containment, Eradication & Recovery](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#-4-containment-eradication--recovery)
- [Post-Incident Activity](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#-5-post-incident-activity)
- [Incident Closure](https://github.com/sunilselvaraj1/Brute-Force-Attack?tab=readme-ov-file#-6-incident-closure)

---

<br>

## ⚙️ 1. Preparation: Alert rule to detect Brute-force attack

A custom KQL detection rule to identify brute-force attempts was created, tested and deployed in Microsoft Sentinel

### **Detection Rule (KQL)**
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedCount = count() by DeviceName, RemoteIP
| where FailedCount >= 5
| order by FailedCount desc
```
Analytics Rule Settings:
- MITRE ATT&CK: T1110 - Brute Force, T1078 - Valid Accounts
- Run query every 4 hours
- Lookup data for last 5 hours
- Stop running query after alert is generated == Yes
- Configure Entity Mappings for the Remote IP and DeviceName
- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

<br>

<img width="1536" height="808" alt="image" src="https://github.com/user-attachments/assets/00a47eba-5f9d-4eb1-b69e-d8f08fd761b6" />
 <img width="1426" height="601" alt="image" src="https://github.com/user-attachments/assets/e4cbb21e-fe66-49b8-bc9b-313b84271871" />  

<br>
<br>

The rule was successfully created, tested, deployed and enabled.

<br>

<img width="1813" height="102" alt="image" src="https://github.com/user-attachments/assets/dab1f2cd-451d-41e1-af16-306cb442b687" />

---

## 🔍 2. Detection & Analysis

### 2.1 Alert Trigger

The rule I deployed, generated an alert for brute-force attempts:

<img width="1845" height="101" alt="image" src="https://github.com/user-attachments/assets/1152af32-180e-45e6-954b-f8277a542417" />

<br>

Incident metadata update:
- Assigned to: Self
- Status: Active
- Severity: Medium

<img width="1436" height="774" alt="image" src="https://github.com/user-attachments/assets/352d4826-dc74-486f-a136-21a1738a4245" />


<br>

### 2.2 Initial Validation

Targeted Devices:
- windows-target-1
- keith-vm-2025

Attacks originated from External IPs:
- 196.219.39.203
- 45.136.68.79
<br>
<img width="1864" height="1008" alt="image" src="https://github.com/user-attachments/assets/8aef7434-d7b9-4d5e-843f-42bde678bf86" />
<br>

### 2.2 Initial Investigation

Created KQL to 
- Get a list of all RemoteIPs that performed brute-force attack against the above mentioned two devices. 
- Get brute-force attempt counts


```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1" or DeviceName == "keith-vm-2025"
| where ActionType == "LogonFailed"
| summarize AttemptCount = count() by DeviceName, RemoteIP
```
<br>
<img width="968" height="847" alt="image" src="https://github.com/user-attachments/assets/a0253cba-5fe6-4655-aba3-2552eb301b94" />

Findings
- **13 RemoteIPs involved** (The original alert showed only 2 RemoteIPs but 11 more attacking RemoteIPs were detected through investigation)
- Maximum failed attempts: 178

### 2.3 Identifying Additional Impacted Devices

I created another KQL query to investigate further if the above list of RemoteIPs attacked any other devices in the network.

```kql
let attackerIP = 
    DeviceLogonEvents
    | where DeviceName in ("windows-target-1", "keith-vm-2025")
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;
DeviceLogonEvents
| where RemoteIP in (attackerIP)
| summarize attemptCount = count() by DeviceName, RemoteIP, ActionType
| order by attemptCount desc
```

Findings: 
- Additional affected device discovered: **leon-test-mde**
- This device was not part of the original alert but was detected through extended investigation.

<img width="965" height="926" alt="image" src="https://github.com/user-attachments/assets/8e6dcf33-10a8-46ee-b280-48da36b45c3e" />


### 3.4 Checking for Successful Login(s)

Created another KQL query to check if there is any successful login was made by the attacker:

```kql
let attackerIP = 
    DeviceLogonEvents
    | where DeviceName in ("windows-target-1", "keith-vm-2025")
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;
DeviceLogonEvents
| where RemoteIP in (attackerIP)
| summarize attemptCount = count() by DeviceName, RemoteIP, ActionType
| distinct ActionType
```
Findings: **NO successful logins detected**. Only LogonFailed events were found

---
## 🚧 4. Containment, Eradication & Recovery

### 4.1 Containment Actions

The following devices were isolated using Microsoft Defender for Endpoint:
- keith-vm-2025
- leon-test-mde
- windows-target-1

<img width="1671" height="943" alt="image" src="https://github.com/user-attachments/assets/618f418a-6ced-4da9-8473-fafe05a80a60" />

<br>

Additional measures:
- Triggered Anti-Virus scans on all affected machines
<img width="1658" height="931" alt="image" src="https://github.com/user-attachments/assets/17458415-7780-4113-bc44-1d8d15880f8e" />
- Collected investigation packages for forensic review
<img width="1661" height="942" alt="image" src="https://github.com/user-attachments/assets/0f28329d-28e1-4962-99d3-d0ce76e29e1b" />
- Suggested to modify NSG rules to allow only internal IP traffic
<img width="1670" height="728" alt="image" src="https://github.com/user-attachments/assets/61fa2598-47e7-47ae-b9cb-79c579adaec3" />

<br>

### 4.2 Eradication

- No successful intrusion detected
- No malicious persistence found
- No eradication steps necessary at this stage

Awaiting AV scan and forensic package results for confirmation

<br>

### 4.3 Recovery

- Devices remain isolated until validated as clean
- Strengthened network restrictions
- Improved monitoring rules for external login attempts

---

## 📚 5. Post-Incident Activity

Lessons Learned
- Custom analytics rules are highly effective for deeper detection.
- NSG restrictions significantly minimise external exposure.
- Logging and monitoring should be expanded to all externally reachable assets.

---

## ✅ 6. Incident Closure

- Updated incident with all the above investigation notes
- Classification: **True Positive**
- Impact: **No compromise. Brute-force attempts blocked successfully.**
- Incident Status: **Closed**
