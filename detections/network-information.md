## Network Information Analysis

This document provides a general guide for analyzing network configurations, active connections, and related artifacts collected by Forensicator.

---

### 🌐 DNS Cache

**🧾 Summary**

This section displays the contents of the local DNS cache, which stores recently resolved domain names and their corresponding IP addresses.

**⚠️ Why This Matters**

The DNS cache is a valuable forensic artifact that shows which domains the system has recently communicated with. It can provide strong indicators of compromise, such as connections to known malicious domains, command-and-control (C2) servers, or suspicious websites.

**🔍 What to Look For**

- **Suspicious or Known-Bad Domains:** Check entries against threat intelligence feeds for domains associated with malware, phishing, or C2 servers.
- **Recently Resolved Domains:** Look for domains resolved around the time of the suspected incident.
- **Anomalous Domain Names:** Be wary of long, randomly generated domain names, which are often used by domain generation algorithms (DGAs) in malware.
- **Low Time-to-Live (TTL) Values:** While not always malicious, very low TTL values can be used by attackers to rapidly change the IP address of their C2 server to evade blocklists.

**🎯 MITRE ATT&CK Mapping**

- **T1568.002 (Dynamic Resolution: Domain Generation Algorithms):** Malware often uses DGAs to generate a large number of domains to connect to, many of which will appear in the DNS cache.

---

### 🔌 Network Connections and Sessions

**🧾 Summary**

This group of artifacts includes current TCP/UDP connections, the processes that own them, and details about active SMB sessions.

**⚠️ Why This Matters**

This is a live look at what the machine is communicating with. It's critical for identifying active malicious connections, unauthorized data transfers, and lateral movement.

**🔍 What to Look For**

- **Connections to Unusual IP Addresses or Ports:** Investigate connections to non-standard ports or IP addresses located in unexpected geographical regions.
- **Processes with Network Connections:** Scrutinize which processes are making network connections. A process like `svchost.exe` making many outbound connections to disparate IPs is a red flag. A word processor making outbound connections is also highly suspicious.
- **`State` of Connections:** `ESTABLISHED` connections are active. A large number of `CLOSE_WAIT` or `TIME_WAIT` connections can sometimes indicate a problem or a specific type of network activity. `LISTENING` ports indicate services waiting for inbound connections.
- **SMB Sessions:** Look for SMB connections (`Outbound` or `Active`) to or from unusual hosts. SMB is a common vector for lateral movement and data exfiltration within a network.

**🎯 MITRE ATT&CK Mapping**

- **T1049 (System Network Connections Discovery):** Attackers inspect network connections to understand the environment.
- **T1021.002 (Remote Services: SMB/Windows Admin Shares):** SMB is frequently used for lateral movement.
- **T1071 (Application Layer Protocol):** Malware uses standard protocols like HTTP, HTTPS, and DNS for C2 communication.

---

### 📜 Firewall Rules

**🧾 Summary**

This section lists the currently configured host-based firewall rules, including their name, direction (inbound/outbound), action (allow/block), and status.

**⚠️ Why This Matters**

Attackers often modify firewall rules to allow their malicious traffic in or out of the compromised machine. They may create a new "allow" rule for their C2 traffic or disable existing rules that might block them.

**🔍 What to Look For**

- **Newly Created "Allow" Rules:** Look for rules, especially for outbound traffic, that allow connections for an unknown application or to a specific IP/port. Check the creation date of the rule if possible.
- **Disabled Rules:** Scrutinize any default security rules that have been disabled.
- **Overly Permissive Rules:** Rules that allow "Any" protocol to "Any" port are dangerous and could be a sign of misconfiguration or malicious activity.
- **Rule Names and Descriptions:** Look for rules with suspicious names or no description, as attackers may be careless when creating them.

**🎯 MITRE ATT&CK Mapping**

- **T1562.004 (Impair Defenses: Disable or Modify System Firewall):** This is the primary technique related to firewall manipulation.

---

### 📶 Wireless Networks

**🧾 Summary**

This section lists the wireless network profiles saved on the system, which can sometimes include their pre-shared keys (passwords) in cleartext.

**⚠️ Why This Matters**

This information provides a history of which wireless networks the device has connected to. For an attacker, this is a source of credentials that can be used to gain access to other networks the user has access to.

**🔍 What to Look For**

- **Unexpected Network Profiles:** Are there saved networks that the user should not have been connected to?
- **Password Exposure:** The presence of cleartext passwords is a significant finding. It indicates that if the device is compromised, all saved Wi-Fi network credentials are also compromised, posing a risk to those networks.

---

### 🛣️ IP Routing Information

**🧾 Summary**

This section details the system's IP routing table, showing which network interfaces are used to send traffic to different destinations.

**⚠️ Why This Matters**

The routing table controls the flow of network traffic. Attackers can potentially manipulate routes to redirect traffic through a machine they control (Man-in-the-Middle) or to ensure their traffic is sent out through a specific, less-monitored interface.

**🔍 What to Look For**

- **Anomalous Default Route:** A system should typically have only one primary default route (`0.0.0.0/0`). Multiple default routes or a default route pointing to an unexpected gateway IP is a red flag.
- **Specific Routes to Suspicious Networks:** Look for static routes that have been added to direct traffic for a specific IP range to an unusual next-hop address.
- **High Metric Values:** A high route metric (`9999`) often indicates a backup or less-preferred route, but could also be used by attackers to create a less-obvious path for their traffic.
