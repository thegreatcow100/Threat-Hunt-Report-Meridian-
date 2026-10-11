# Threat Hunt Report: Meridian

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 10 host

- **Languages & Tools:** Kusto Query Language (KQL)

---

## Scenario Summary
Meridian's portal threw a real incident overnight. Single host, web app in front of a patient database, and a defence stack that has been fighting back automatically the whole time. Some of what it caught is the real intrusion. This hunt focuses on separating the attacker's actions from the noise and determining if the system is still infected. 
