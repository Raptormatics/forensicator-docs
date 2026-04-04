## Forensicator Extras Analysis

This document provides a general guide for analyzing the supplementary artifacts and deeper collection modules included in the "Extras" section of the Forensicator report. These modules often perform deeper, more time-consuming analysis or collect large volumes of data.

---

### 📜 Group Policy Report (GPOReport.html)

**🧾 Summary**

This artifact is an HTML report detailing the Group Policy Objects (GPOs) applied to the user and computer. GPOs are used by administrators to enforce security settings, deploy software, and manage the operating environment.

**⚠️ Why This Matters**

GPO settings dictate the security posture of the system. Attackers may attempt to modify GPOs to weaken security controls. Analyzing the GPO report helps an investigator understand the intended security configuration and identify any deviations or weak settings that could be exploited.

**🔍 What to Look For**

- **Weak Password Policies:** Look for policies that don't enforce password complexity, length, or history.
- **Permissive User Rights:** Identify policies that grant excessive privileges to standard users (e.g., "Log on as a service," "Debug programs").
- **Firewall Policy:** Check for GPOs that modify the host firewall to allow unexpected traffic.
- **Disabled Security Features:** Look for policies that disable security features like Windows Defender, logging, or UAC (User Account Control).

---

### 🧠 WINPMEM RAM CAPTURE (/RAM)

**🧾 Summary**

This artifact is a full memory dump (RAM capture) of the live system, typically captured using tools like WinPmem.

**⚠️ Why This Matters**

A memory dump is one of the most valuable artifacts in digital forensics. It contains a snapshot of everything running on the system at the time of capture, including active processes, network connections, loaded drivers, and potentially even decrypted data, passwords, or encryption keys. It is essential for detecting fileless malware that runs only in memory and leaves few traces on the hard disk.

**🔍 What to Look For**

This artifact cannot be analyzed directly in a text editor. It requires specialized memory forensics tools like **Volatility** or **Rekall**.

- **Running Processes:** Use memory analysis tools to list all running processes and compare them against disk-based artifacts.
- **Malicious Code Injection:** Look for signs of process hollowing, DLL injection, or other code injection techniques.
- **Network Artifacts:** Extract active and recent network connections to identify potential C2 communications.
- **Registry Keys:** Volatility can be used to see registry keys as they existed in memory.
- **Passwords and Credentials:** It is sometimes possible to extract cleartext passwords or password hashes from memory.

**🎯 MITRE ATT&CK Mapping**

- **T1003 (OS Credential Dumping):** Memory dumps can contain credentials.
- **T1057 (Process Discovery):** Analyzing memory is a key way to discover running processes.

---

### 🌐 Browsing History Dump (/BROWSING_HISTORY)

**🧾 Summary**

This artifact is a collection of browsing history, cache, and download records from various web browsers installed on the system (e.g., Chrome, Firefox, Edge).

**⚠️ Why This Matters**

Browser history provides a clear timeline of a user's web activity. It can reveal how a compromise occurred (e.g., visiting a malicious website, downloading a trojan), identify phishing attempts, and uncover data exfiltration to cloud storage sites.

**🔍 What to Look For**

- **Suspicious Domains:** Look for visits to known malicious or suspicious websites.
- **Downloads:** Analyze the list of downloaded files. Pay close attention to executables (`.exe`, `.msi`) or script files downloaded from untrusted sources.
- **Phishing Sites:** Identify visits to sites that mimic legitimate login pages.
- **Webmail and Cloud Storage:** Note any access to personal webmail or cloud storage sites, as these are common channels for data exfiltration.

---

### 📡 Network Trace (/PCAP)

**🧾 Summary**

This is a network packet capture (`.pcap` or `.etl` file) that contains a recording of the raw network traffic to and from the machine for a period of time.

**⚠️ Why This Matters**

A packet capture provides the most granular level of detail about network communications. It allows an investigator to reconstruct conversations, extract files, and analyze protocol-level details that are not visible in a simple list of network connections.

**🔍 What to Look For**

This artifact requires specialized tools like **Wireshark** or **tcpdump** for analysis.

- **Unencrypted Protocols:** Look for sensitive data being transmitted over unencrypted protocols like HTTP, FTP, or Telnet.
- **C2 Beaconing:** Identify regular, periodic connections to an external IP address, which may indicate command-and-control beaconing.
- **Data Exfiltration:** Look for large outbound data flows to unexpected destinations.
- **DNS Queries:** Analyze DNS requests to spot queries for malicious domains.
- **Suspicious Payloads:** Inspect the content of packets for malicious scripts, exploits, or file transfers.

---

### 📂 Other Collections

**🧾 Summary**

This section covers other bulk data collection modules that may be triggered based on the Forensicator configuration.

**⚠️ Why This Matters**

These provide deeper, more specific context for certain types of investigations.

**🔍 What to Look For**

- **EVENT LOGS (/EVTXLOGS):** A full backup of the Windows Event Logs. This is invaluable for deep timeline analysis, tracking user logons, process creation, and system errors.
- **IIS Logs (/IISLogs):** If the system is a web server, these logs contain a record of every HTTP request made to the server, essential for investigating web-based attacks.
- **Discovered Log4j (/LOG4J):** The output of a scan for systems vulnerable to the Log4j vulnerability.
- **Matched Hashes (/HashMatches):** If a file hashing module is run, this will contain a list of files on the system that matched a list of known-bad hashes. This is a very strong indicator of compromise.
