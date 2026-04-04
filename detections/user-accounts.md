## User Accounts and Permissions Analysis

This document provides a general guide for analyzing user accounts, logon sessions, and related security artifacts collected by Forensicator. Each section outlines what to look for and the security implications of potential findings.

---

### 🔑 Current User Information {#current-user-information}

**🧾 Summary**

This section identifies the user context in which the Forensicator script was executed. It typically includes a username, domain/hostname, and a User UUID or Security Identifier (SID).

**⚠️ Why This Matters**

Identifying the user context is fundamental to digital forensics. It establishes a baseline of activity and helps attribute actions on the system to a specific account.

- **Establishes Context:** Links system activity, file modifications, and network connections to a specific user account.
- **Scope of Compromise:** Understanding if the script was run as a standard user or an administrator helps define the scope of visibility and potential compromise.

**🔍 What to Look For**

- **User Identity:** Is the user account a standard user, an administrator, or a system/service account?
- **Account Context:** Is the user a local account or a domain-joined account? This provides clues about the environment (standalone vs. corporate).
- **UUID/SID:** The unique identifier can be used to track the user's activity across other logs and artifacts.

---

### 🖥️ System Details {#system-details}

**🧾 Summary**

This section provides a snapshot of the system's identity, including its name, domain/workgroup, and basic hardware information.

**⚠️ Why This Matters**

While not directly about user accounts, system details provide critical context for any investigation.

- **Asset Identification:** Confirms the evidence was collected from the correct machine.
- **Environment Context:** Indicates whether the system is part of a corporate domain, which might imply centralized management and logging, or a standalone workgroup, which may have less stringent security.

---

### 🔐 Logon Sessions {#logon-sessions}

**🧾 Summary**

This section displays active and recent user logon sessions, including the username, session type (e.g., console, RDP), and logon time.

**⚠️ Why This Matters**

Logon sessions are a primary target for analysis to detect unauthorized access, lateral movement, and persistence.

**🔍 What to Look For**

- **Unusually Long Idle Times:** Extremely long idle times can indicate a forgotten-but-active session or a dormant attacker foothold.
- **Unexpected Session Types:** Remote logins (RDP) on systems that should not have them enabled are a major red flag.
- **Multiple Sessions:** An single user with multiple, concurrent sessions could be normal, or it could indicate session hijacking or unauthorized multi-tasking.
- **Anomalous Logon Times:** Logins occurring outside of normal business hours should be scrutinized.
- **Unexpected Usernames:** Sessions from service accounts, disabled accounts, or unrecognized users are highly suspicious.

**🎯 MITRE ATT&CK Mapping**

- **T1078 (Valid Accounts):** Attackers use legitimate credentials to establish and maintain access.
- **T1021 (Remote Services):** Remote logon sessions can be indicative of lateral movement.

---

### 🏃 User Processes {#user-processes}

**🧾 Summary**

This section lists processes running under the context of specific users, including system and service accounts.

**⚠️ Why This Matters**

Analyzing running processes is crucial for detecting malware, unauthorized software, and "living-off-the-land" techniques where attackers abuse legitimate system tools.

**🔍 What to Look For**

- **High-Privilege Processes:** Scrutinize processes running as `NT AUTHORITY\SYSTEM` or `root`. Attackers aim to execute code with the highest privileges.
- **Suspicious Execution Paths:** Processes running from non-standard locations (e.g., `C:\Windows\Temp`, `/tmp`, `AppData`, user download folders) are suspicious. Legitimate software usually runs from `Program Files` or `System32`.
- **Anomalous Resource Usage:** Unusually high CPU or memory usage can indicate malicious activity like crypto-mining or data exfiltration.
- **Misspelled or Obfuscated Names:** Look for common process names that are slightly misspelled (e.g., `svch0st.exe`).

---

### 👤 User Profiles {#user-profiles}

**🧾 Summary**

This section lists user profiles on the system, their unique Security Identifiers (SIDs), and their last usage timestamp.

**⚠️ Why This Matters**

User profiles contain a wealth of forensic data and can reveal all accounts that have ever been used on the system.

**🔍 What to Look For**

- **Unrecognized or Unauthorized Profiles:** The existence of a user profile that cannot be explained or is not authorized is a sign of a breach.
- **Last Used Timestamps:** A dormant or old profile that suddenly becomes active is a major red flag for account compromise. Conversely, the timestamp can help establish a timeline of when a user was last active.
- **Profile Path:** The location of the user profile folder is typically standardized. Non-standard paths could indicate an attempt to hide a profile.

---

### 🛡️ Administrator Accounts {#administrator-accounts}

**🧾 Summary**

This section lists all accounts that are members of the local `Administrators` group.

**⚠️ Why This Matters**

Administrator accounts are the "keys to the kingdom." Compromise of any one of these accounts can lead to a full system compromise.

**🔍 What to Look For**

- **Excessive Admins:** The principle of least privilege dictates that the number of admin accounts should be minimal. Every additional admin account increases the attack surface.
- **Enabled Built-in Administrator:** The default, built-in `Administrator` account should typically be disabled. If it is enabled, its purpose should be justified and its password exceptionally strong.
- **Standard Users with Admin Rights:** User accounts used for daily tasks (email, web browsing) should not have administrative privileges.

**🎯 MITRE ATT&CK Mapping**

- **T1078.003 (Valid Accounts: Local Accounts):** The abuse of local administrator accounts is a common technique for privilege escalation and persistence.

---

### 👥 Local Groups {#local-groups}

**🧾 Summary**

This table lists the local user groups configured on the machine and their purpose.

**⚠️ Why This Matters**

Local groups are a primary mechanism for managing permissions. Attackers often target group memberships to escalate privileges.

**🔍 What to Look For**

- **Membership of Privileged Groups:** Scrutinize the membership of powerful groups beyond just `Administrators`. These include:
    - `Remote Desktop Users`: Allows remote login.
    - `Backup Operators`: Can bypass file system permissions.
    - `Power Users`: A legacy group that can grant extensive, often unexpected, permissions.
- **Custom vs. Default Groups:** Identify any custom-created groups. Understand their intended purpose and verify their membership.
- **Suspicious Group Names:** Attackers may create a new local group with a deceptive name to try and blend in.
- **Investigation Steps**
A full investigation requires enumerating the members of each sensitive group to ensure only authorized accounts are included. This data provides the necessary context for that deeper analysis.

