## Detection and Threat Intelligence Analysis

This document provides a general guide for interpreting the output of Forensicator's active detection modules. These modules use threat intelligence and behavioral analytics to find direct evidence of malicious activity.

---

### 🛡️ Sigma Rules

**🧾 Summary**

This section displays matches from Sigma, a generic signature format for SIEM systems that can be used to describe log events. Forensicator uses a set of Sigma rules to scan event logs for known malicious or suspicious patterns of activity.

**⚠️ Why This Matters**

Sigma is a powerful, open standard for detecting attacker techniques. A Sigma match is a high-confidence indicator of compromise that directly points to a specific behavior seen on the system, such as a particular command being run or a specific type of authentication event.

**🔍 What to Look For**

- **Rule Title and Level:** The rule title gives a clear description of the detected activity (e.g., "Suspicious PowerShell Command"). The `Level` (e.g., critical, high, medium) indicates the severity and confidence of the finding.
- **MITRE ATT&CK Tags:** These tags map the detected behavior directly to a known attacker tactic or technique in the MITRE ATT&CK framework, providing immediate context for the alert.
- **Event Details:** The log entry that triggered the match provides the raw data. Pay close attention to:
    - **User:** Who performed the action?
    - **Process:** What program was used?
    - **CommandLine / ScriptBlock:** What specific command or script was executed? This is often where the most incriminating evidence is found.

---

### 🏴‍☠️ Ransomware Artifacts

**🧾 Summary**

This group of checks looks for common indicators of ransomware activity, such as ransom notes, known file extensions, and attempts to delete volume shadow copies.

**⚠️ Why This Matters**

These are direct, high-confidence indicators of a ransomware infection. Early detection of these artifacts is critical for response.

**🔍 What to Look For**

- **Ransomware Notes:** The presence of a file on disk that matches the text of a known ransom note is a definitive sign of compromise.
- **Ransomware Extension:** The module checks for files that have been renamed with file extensions used by known ransomware families (e.g., `.lockbit`, `.crypted`).
- **High Entropy Files:** Ransomware encrypts files, and encrypted data has very high entropy (randomness). This check flags files with abnormally high entropy, which could be encrypted files. This is a strong, though not definitive, indicator.
- **Shadow Copy Deletion:** Ransomware's first step after infection is often to delete volume shadow copies to prevent the victim from easily recovering their files. This check looks for the specific commands used to perform this action (e.g., using `vssadmin.exe` or `wmic.exe`).

**🎯 MITRE ATT&CK Mapping**

- **T1486 (Data Encrypted for Impact):** The core ransomware tactic.
- **T1490 (Inhibit System Recovery):** The technique of deleting shadow copies to hamper recovery efforts.

---

### #️⃣ Malicious Hash Check

**🧾 Summary**

This module calculates the cryptographic hash (MD5, SHA256) of files on the system and compares them against a list of known-malicious file hashes.

**⚠️ Why This Matters**

A hash match is a definitive indicator that a specific, known-malicious file is present on the system. Because cryptographic hashes are unique, this method provides a very high-confidence detection with virtually no false positives.

**🔍 What to Look For**

- **Any Match:** Any file that gets a hit from this module should be treated as malicious.
- **File Details:** Once a match is found, pivot to the other details provided:
    - **File:** The full path to the malicious file. This tells you where the malware is located.
    - **Owner:** Who owns the file.
    - **Timestamps:** `Created` and `Last Modified` dates are crucial for building a timeline of the infection.
