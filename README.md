# Threat Hunt Report: Meridian

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host

- **Languages & Tools:** Kusto Query Language (KQL)

---

## Scenario Summary
Meridian's portal threw a real incident overnight. Single host, web app in front of a patient database, and a defence stack that has been fighting back automatically the whole time. Some of what it caught is the real intrusion. This hunt focuses on separating the attacker's actions from the noise and determining if the system is still infected. 

---
## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – Fake Antivirus Dropper
- **Answer:** 4, nmap, curl, whatweb, gobuster
- **Notes:** Recognising the recon toolchain tells you the attacker's skill level and methodology. In this case, the progression shows methodical recon: port discovery, manual look, tech stack ID, then exhaustive directory enumeration. An attacker who runs WhatWeb between curl and gobuster is fingerprinting the tech stack to choose the right wordlist.

```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where EventTime_t < datetime(2026-02-06 05:55:00)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen=min(EventTime_t), Requests=count() by UserAgent_s
| order by FirstSeen asc
```

<img width="1333" height="228" alt="Meridian flag 1" src="https://github.com/user-attachments/assets/f8454612-4ef7-4e12-9a06-e82c64d8144e" />

Now that we know the reconnaissance tools that the attackers used, we need to figure out how they gained access to the system and what they changed. 
---

## 🧠 Summary Table
| Flag | Description                        | Value | MITRE ATT&CK | Definiton |
|------|------------------------------------|---------------------|---------------------|---------------------|
| 1    | Attackers Reconnaissance Tools     | nmap, curl, whatweb, gobuster | T1595 | Active Scanning |
| 2a   | Endpoint Accessed                  | config_viewer.php | T1190 | Exploit Public-Facing Application |
| 2b   | Files Accessed                     | /etc/passwd, database.conf | T1552.001 | Credentials In Files |
| 3a   | Real Account Utilized              | svc_backup | T1078 | Valid Accounts |
| 3b   | Failed Access Attempts             | sudo and SSH root login | T1078 | Valid Accounts |
| 4    | Privilege Escalation Pivot         | /tmp/rootbash -p | T1548.001 | Setuid and Setgid |
| 5    | Maintaining Persistence            |/opt/meridian/scripts/health_check | T1036.005 | Match Legitimate Name or Location |
| 6    | Open Backdoor                      | 10.1.134.57:43212, not neutralised | T1071 | Application Layer Protocol |
| 7a   | Data Stolen                        | Patient data | T1213 | Data from Information Repositories |
| 7b   | Tampered File                      | backup.conf | T1565.001 | Stored Data Manipulation |
| 8    | Removed Vital Service              | sysmon, removes process- level monitoring | T1562.001 | Impair Defenses: Disable or Modify Tools |
| 9a   | Capturing Evidence                 | AVML, /tmp/evidence/memory.lime | T1005 | Data from Local System |
| 9b   | Remediation                        | Remove the SUID-root health_check binary from the scripts directory | T1036.005 | Match Legitimate Name or Location |

---

## 🛡️ Response Actions Taken
- Secured configuration files to prevent access to account credentials.
- Removed the SUID-root health_check binary from the scripts directory.
- Re-added sysmon.service (enabling process-level monitoring).
- Adjusted remediation scan parameters with a proper baseline to ensure it does not delete important system files and services.


---

## 📘 Lessons Learned
- Check backup configurations for tampering, as attackers can use them to maintain persistence.
- Ensure databases and containing credentials are secured. Attackers who gain access to these credentials can log in through real accounts.
- Routinely check scan baselines to make sure that they are not misconfigured in any detrimental way.

