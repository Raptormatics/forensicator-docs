## Event Log Analysis Guide

This document provides a general guide for analyzing key Windows Event Log (`.evtx`) artifacts. Windows Event Logs are a primary source of evidence for forensic investigations, recording detailed information about system, security, and application events.

---

### 🔑 Logon Events (Security Log)

**🧾 Summary**

This section analyzes logon and logoff activity, providing crucial insights into who has accessed the system, when, and from where. The primary Event IDs are `4624` (Successful Logon) and `4625` (Failed Logon).

**⚠️ Why This Matters**

Logon events are fundamental to tracking attacker movement. They can reveal brute-force attempts, lateral movement, unauthorized access, and privilege escalation.

**🔍 What to Look For**

- **Logon Type:** This is one of the most critical fields.
    - **Type 2 (Interactive):** Logon at the physical console.
    - **Type 3 (Network):** Accessing a file share (SMB). Common for lateral movement.
    - **Type 10 (RemoteInteractive):** An RDP (Remote Desktop) session. Extremely important to scrutinize.
    - **Type 5 (Service):** A service starting.
- **Failed Logons (4625):** A large volume of failed logons from a single source IP may indicate a brute-force or password-spraying attack. Failed logons for administrative accounts are particularly noteworthy.
- **Successful Logons (4624):**
    - **Source Network Address:** Logons from unexpected or external IP addresses are a major red flag. Logons from other internal machines can indicate lateral movement.
    - **Anomalous Hours:** Logons occurring outside of standard business hours.
    - **Unusual Accounts:** Logons by service accounts, disabled accounts, or accounts that should not be used for interactive sessions.

**🎯 MITRE ATT&CK Mapping**

- **T1078 (Valid Accounts):** A successful logon is a direct example of this.
- **T1110 (Brute Force):** Indicated by a high volume of failed logon events.
- **T1021 (Remote Services):** Logon Type 10 (RDP) or Type 3 (SMB) can be evidence of lateral movement.

---

### 🏃 Process Execution Events (Security Log)

**🧾 Summary**

This section details process creation events, captured by Event ID `4688` (if enabled). It records when a process was started, by whom, and its command line.

**⚠️ Why This Matters**

Tracking process execution provides a detailed "fingerprint" of what has been run on a system. It is invaluable for detecting the execution of malware, scripts, and suspicious built-in system tools.

**🔍 What to Look For**

- **`CommandLine`:** This is the most important field. Look for:
    - Execution of interpreters like `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, or `mshta.exe`.
    - Obfuscated commands, especially Base64 encoded PowerShell commands.
    - Use of "Living-off-the-Land" Binaries (LOLBins) like `certutil.exe` to download files or `rundll32.exe` to execute malicious code.
- **`Parent Process`:** Analyze the parent-child relationship. A legitimate system process like `services.exe` should not be spawning `cmd.exe`. A Microsoft Office application spawning `powershell.exe` is a classic indicator of a malicious document.
- **Suspicious Executable Paths:** Processes being launched from temporary directories, user download folders, or other non-standard locations.

**🎯 MITRE ATT&CK Mapping**

- **T1059 (Command and Scripting Interpreter):** Directly observed through the execution of PowerShell, cmd, etc.
- **T1204 (User Execution):** Captures the initial execution of malware, often triggered by a user action.

---

### 👤 User and Group Management Events (Security Log)

**🧾 Summary**

This section covers events related to the creation, deletion, and modification of user accounts and groups.

**⚠️ Why This Matters**

Attackers often create new accounts for persistence, add compromised users to privileged groups to escalate their permissions, or modify existing accounts to maintain access.

**🔍 What to Look For**

- **User Creation (4720):** Any unexpected user creation is highly suspicious.
- **User Added to Privileged Group (4728, 4732, 4756):** An alert for a user being added to a group like `Administrators`, `Remote Desktop Users`, or `Domain Admins` is a critical finding and a common sign of privilege escalation.
- **Password Reset (4724):** A password reset for a user, especially an administrative one, could indicate an attacker taking control of an account.
- **Account Disabled/Enabled (4725, 4722):** An attacker might disable a security-related account or re-enable a previously dormant one.

**🎯 MITRE ATT&CK Mapping**

- **T1136 (Create Account):** Directly maps to Event ID 4720.
- **T1098 (Account Manipulation):** Covers adding users to groups, resetting passwords, and other modifications.

---

### 📂 Object Access Events (Security Log)

**🧾 Summary**

If enabled, this logging category records when specific objects, such as files or registry keys, are accessed.

**⚠️ Why This Matters**

Object access logging can provide highly granular evidence of an attacker's activities, such as accessing sensitive files, reading credentials from the registry, or modifying critical system files. However, it is very verbose and often disabled by default.

**🔍 What to Look For**

- **Access to Sensitive Files:** Look for unexpected processes accessing files in user directories, system configuration folders, or locations with sensitive data.
- **Registry Access:** Monitor for access to sensitive registry keys, particularly those related to credentials (e.g., `SAM`, `SECURITY`, `LSA Secrets`) or persistence (`Run` keys).
- **`Accesses` Field:** This field details *what* the process did (e.g., `ReadData`, `WriteData`, `Delete`). A process deleting a critical file is a major indicator.
