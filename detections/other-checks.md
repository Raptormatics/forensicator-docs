## Analysis of Other System Checks

This document provides a general guide for analyzing the miscellaneous system artifacts collected by Forensicator. These checks often provide valuable context about system usage, user behavior, and potential avenues for compromise.

---

### 🔌 Device and Drive Information

**🧾 Summary**

This category covers information about physical and logical drives, including connected USB devices, webcams, and a history of previously connected drives.

**⚠️ Why This Matters**

This information helps build a profile of how the system is used and what external devices have interacted with it. It's crucial for tracking data exfiltration, identifying unauthorized hardware, and understanding the system's physical environment.

**🔍 What to Look For**

- **Previously Connected Drives:** The list of all previously connected USB drives is a key artifact. Look for unrecognized devices, as they could have been used to introduce malware or exfiltrate data. The `Serial` number can be used to track a specific physical device.
- **Logical Drives:** Note the available drives and their free space. A sudden, unexplained drop in free space might indicate a large data staging operation.
- **USB Devices / UPNPDevices:** This provides a broader view of all connected hardware. Look for any unusual or unauthorized devices, such as rogue network adapters or unknown input devices.

**🎯 MITRE ATT&CK Mapping**

- **T1200 (Hardware Additions):** An attacker might introduce unauthorized hardware.
- **T1052.001 (Exfiltration Over Physical Medium: Exfiltration over USB):** The history of USB drives is direct evidence related to this technique.

---

### 📜 PowerShell Command History

**🧾 Summary**

This section displays the command history from the user's PowerShell sessions, providing a log of commands that have been typed into the console.

**⚠️ Why This Matters**

PowerShell is a powerful tool for both administrators and attackers. The command history provides a direct view into how PowerShell has been used on the system. It can reveal reconnaissance activity, execution of malicious scripts, and attempts to disable security features, often in the attacker's own words.

**🔍 What to Look For**

- **Suspicious Commands:** Look for commands related to:
    - **Reconnaissance:** `Get-Process`, `Get-NetTCPConnection`, `Get-LocalGroupMember`.
    - **Execution:** `Invoke-Expression`, `IEX`, `New-Object Net.WebClient).DownloadString`.
    - **Defense Evasion:** `Set-MpPreference -DisableRealtimeMonitoring $true`.
- **Encoded Commands:** Look for the use of `-EncodedCommand` or `-e`, which are common methods for obfuscating malicious scripts.
- **File Downloads:** Search for commands that download files from the internet, especially from non-standard domains or IP addresses.
- **Script Execution:** Note any execution of `.ps1` files.

---

### 📂 Executables in Unusual Locations

**🧾 Summary**

This set of checks searches for executable files (`.exe`) in non-standard locations where software is not typically installed, such as `Downloads`, `AppData`, `Documents`, `Temp`, and `Perflogs`.

**⚠️ Why This Matters**

Legitimate software is almost always installed in `C:\Program Files` or `C:\Program Files (x86)`. Malware, on the other hand, is often dropped into folders that the standard user account has write permissions for. Finding an executable in one of these "unusual" locations is a significant red flag.

**🔍 What to Look For**

- **Any Executable:** Treat any executable found in these locations as suspicious until it can be verified.
- **Downloads Folder:** Users often run malicious installers directly from their Downloads folder. Scrutinize all executables here.
- **AppData and Temp:** These locations are common hiding places for malware to achieve persistence or stage its components.
- **Timestamps:** Correlate the `CreationTimeUTC` of the executable with the suspected time of compromise.

**🎯 MITRE ATT&CK Mapping**

- **T1036 (Masquerading):** Attackers may give their executables legitimate-sounding names to blend in.
- **T1204.002 (User Execution: Malicious File):** A user running an executable from their Downloads folder is a direct example of this technique.

---

### 🔗 Link Files (.LNK)

**🧾 Summary**

This section lists recently created or modified LNK files. These are shortcuts that point to another file or program.

**⚠️ Why This Matters**

Attackers abuse LNK files for both initial access and persistence. A malicious LNK file can be crafted to execute a malicious script or binary when a user clicks on it, often while still appearing to open a legitimate document.

**🔍 What to Look For**

- **Target Path:** Where does the shortcut point? A LNK file on the desktop pointing to `powershell.exe` in a hidden directory is highly suspicious.
- **Arguments:** The arguments field can contain malicious commands or scripts that are passed to the target executable.
- **Unusual Icons:** Attackers may change the icon of a malicious LNK file to make it look like a harmless document (e.g., a PDF or Word icon).
- **Location:** Look for LNK files in unusual places, such as startup folders for persistence.
