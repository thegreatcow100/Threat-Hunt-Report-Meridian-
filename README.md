# Threat Hunt Report: Meridian

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host

- **Languages & Tools:** Kusto Query Language (KQL)

---

## Scenario Summary
Meridian's portal threw a real incident overnight. Single host, web app in front of a patient database, and a defence stack that has been fighting back automatically the whole time. Some of what it caught is the real intrusion. This hunt focuses on separating the attacker's actions from the noise and determining if the system is still infected. 

---
## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – The Recon Playbook
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
### 🏁 Flag 2a – Initial Access: Traversal Point
- **Answer:** config_viewer.php
- **Discovery:** config_viewer.php, requested directly at 03:52:29, before the gobuster wordlist scan starts at 03:55:05. A deliberate, pre-scan request to a specific vulnerable endpoint indicates prior reconnaissance or leaked intelligence about the application.
- **Key Timestamp:** 2026-02-06T03:52:29Z


```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where EventTime_t < datetime(2026-02-06 03:55:00)
| project EventTime_t, RequestUri_s, UserAgent_s
| order by EventTime_t asc
```

<img width="517" height="202" alt="Meridian Flag 2a" src="https://github.com/user-attachments/assets/cacee12a-c5c0-4dae-83e5-2bd6966225dd" />

---

### 🏁 Flag 2b –  Initial Access: What They Pulled
- **Answer:** /etc/passwd, database.conf
- **Discovery:** /etc/passwd was first pulled (04:07:59, 3077 bytes), then database.conf (04:08:34, 1231 bytes). This matters because the gap between the two actions shows deliberate, sequential exploitation, not automated scanning. The passwd file gives valid usernames; database.conf gives reusable credentials.

```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where EventTime_t < datetime(2026-02-06 05:55:00)
| where RequestUri_s has "config_viewer" and RequestUri_s has "file="
| where StatusCode_s == "200"
| extend Decoded = url_decode(RequestUri_s)
| project EventTime_t, Decoded, ResponseSize_s
| order by EventTime_t asc
```
<img width="564" height="87" alt="Meridian Flag 2b" src="https://github.com/user-attachments/assets/63c2c8e5-7d8e-4f02-8d28-db77c5b3bd4b" />

The attacker has gained access to the system. Which methods worked, and which failed?

---

### 🏁 Flag 3a – Borrowed Access: Method that Worked
- **Answer:** svc_backup
- **Discovery:** svc_backup, "Accepted password for svc_backup from 10.1.134.57" at 04:09:31, only 57 seconds after database.conf was read. Credential reuse from the config file. The attacker didn't need to brute-force the login; they read the password from the database.conf file.
- **Key Timestamp:** 2026-02-06T04:09:31Z

```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 04:08:00)
| where RawMessage_s has "Accepted password" and RawMessage_s has "10.1.134.57"
| parse RawMessage_s with * "Accepted password for " User " from " SrcIp " port" *
| project EventTime_t, User, SrcIp, RawMessage_s
| order by EventTime_t asc
```
<img width="776" height="168" alt="meridian Flag 3a" src="https://github.com/user-attachments/assets/7a7bb3c3-8824-4a6b-bf93-8051b900030a" />

---

### 🏁 Flag 3b – Borrowed Access: Methods that Failed
- **Answer:**  sudo (command not allowed for svc_backup) and SSH root login (failed, 4 attempts rejected)
- **Discovery:** The attacker tried two other ways to get root access on the compromised host and failed. The first was utilizing sudo. svc_backup ran sudo but got 'command not allowed'. The account has no sudo privileges configured. The second was through SSH. There were four failed login attempts, two from localhost (10.1.15.67) and two from the attacker IP (10.1.134.57). Root password authentication is either disabled or the attacker didn't have the password. 
- **Key Timestamp:** sudo (2026-02-06T04:15:07Z) & SSH (2026-02-06T04:44:59Z - 2026-02-06T04:45:41Z)

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 04:08:00)
| where EventCategory_s has_any ("AUTH", "SSH")
| where RawMessage_s has_any ("Failed", "not allowed")
| project EventTime_t, RawMessage_s
```

<img width="1018" height="172" alt="Meridian flag 3b" src="https://github.com/user-attachments/assets/5137896d-84c8-4a84-b4c7-38c01bce2354" />

---

### 🏁 Flag 4 – The Planted Root Shell
- **Answer:** /tmp/rootbash -p
- **Discovery:** /tmp/rootbash -p, executed by svc_backup with euid=0. The -p flag preserves SUID privileges on a bash copy. This is the privilege escalation pivot. 
- **Key Timestamp:** 2026-02-06T04:40:15Z

```kql
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 04:08:00)
| where Types_s has "EXECVE"
| where auid_s == "1001" and euid_s == "0"
| project EventTime_t, Argv_s, exe_s, cwd_s, uid_s
| order by EventTime_t asc
```

<img width="603" height="193" alt="Meridian Flag 4" src="https://github.com/user-attachments/assets/e960caa3-829b-4617-9491-b83fa0c7d528" />

The attacker has escalated their account privileges. Their next step is to gain persistence on the system. Find out how they did it and how it survived.

---

### 🏁 Flag 5a – Persistence: The Second Foothold 
- **Answer:** /opt/meridian/scripts/health_check
- **Discovery:** /opt/meridian/scripts/health_check, real UID 1001 (svc_backup), effective UID 0, PPid 1 (orphaned). Hidden in the app's own scripts folder with a name that reads as routine maintenance. This is the durable persistence mechanism. Unlike /tmp/rootbash, this location blends into the legitimate application structure and survives the automated sweep. 
- **Key Timestamp:** 2026-02-06T05:30:00Z

```kql
MeridianSnapshot_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 04:08:00)
| where ProcBeaconPPid_s == "1"
| where ProcBeaconUid_s has "1001"
| project EventTime_t, ProcBeaconPid_s, ProcBeaconPPid_s, ProcBeaconName_s, ProcBeaconExeLink_s, ProcBeaconUid_s
| order by EventTime_t asc
```

<img width="1311" height="222" alt="Meridian Flag 5a" src="https://github.com/user-attachments/assets/07617f04-365c-4baf-877f-36279eb8e8d8" />

---

### 🏁 Flag 5b – Persistence: Why it Survived
- **Answer:**  The sweep only cleans SSH keys, crontabs, temp directories, SUID files in watched paths, and systemmd services. The script isn't one of these five, so it was never removed.
- **Discovery:** The automated defence caught the /tmp shell in its next sweep and killed it. It caught this second one too -- flagged it as non-baseline, in the log, in plain sight. It's still running. This is the critical detection-remediation gap. The automated tooling flagged it as non-baseline in every sweep but had no remediation rule for scripts in application directories.

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t > datetime(2026-02-06 04:08:00)
| where RawMessage_s has_any ("/tmp", "baseline", "kill", "terminat", "remov", "quarantin", "SUID", "setuid", "scripts")
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

<img width="635" height="376" alt="Meridian Flag 5b" src="https://github.com/user-attachments/assets/2d81926a-b36c-4670-a2fe-87fff63a7401" />

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

