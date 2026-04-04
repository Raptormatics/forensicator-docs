## System Process and Persistence Analysis

This document provides a general guide for analyzing running processes, services, and common persistence mechanisms collected by Forensicator.

---

### 🏃 Processes

**🧾 Summary**

This section lists the currently running processes on the system at the time of collection. It includes details such as Process ID (PID), name, file path, start time, and the product/company it belongs to.

**⚠️ Why This Matters**

The process list is a snapshot of all software actively running on the machine. It is one of the most critical artifacts for finding live malware, identifying unauthorized activity, and understanding what the system is doing.

**🔍 What to Look For**

- **Suspicious Process Names:** Look for names that are misspelled versions of legitimate processes (e.g., `svch0st.exe`), are randomly generated (e.g., `a73hsd8.exe`), or are known malware.
- **Unsigned Processes:** While not all unsigned processes are malicious, malware frequently lacks a valid digital signature. Scrutinize processes without a verified publisher.
- **Execution from Abnormal Locations:** Processes running from user profiles (`AppData`), temporary directories (`C:\Windows\Temp`), or network shares are highly suspicious. Legitimate system processes typically run from `C:\Windows\System32`.
- **Anomalous Start Times:** A process starting around the time of a suspected compromise is a key indicator.
- **Processes with No Parent or an Unexpected Parent:** Analyze the process tree. A legitimate-looking process spawned by an unusual parent (e.g., `winword.exe` spawning `powershell.exe`) is a major red flag.

**🎯 MITRE ATT&CK Mapping**

- **T1057 (Process Discovery):** Attackers enumerate processes to understand the environment and find targets.
- **T1036 (Masquerading):** Malware may be named to mimic legitimate software.

---

### 🚀 Startup Programs

**🧾 Summary**

This section enumerates programs that are configured to launch automatically when a user logs in. This is typically sourced from Registry keys (like `Run`) and filesystem `Startup` folders.

**⚠️ Why This Matters**

Autostart locations are the most common technique attackers use to achieve persistence. By placing their malware in a startup location, they ensure it will re-launch after a system reboot.

**🔍 What to Look For**

- **Unfamiliar Programs:** Any program in the startup list that isn't recognized, expected, or from a trusted vendor requires investigation.
- **Commands with Obfuscated Scripts:** Look for startup commands that launch interpreters like `powershell.exe`, `cmd.exe`, or `wscript.exe`, especially with encoded or suspicious-looking arguments.
- **Executables in Temporary or User-Specific Paths:** A legitimate installer might place a temporary item here, but persistent malware often runs directly from a user's `AppData` folder.
- **Location:** Note the location (`HKCU` vs. `HKLM`). An entry in `HKEY_LOCAL_MACHINE` will run for all users on the system, while `HKEY_CURRENT_USER` only runs for a specific user.

**🎯 MITRE ATT&CK Mapping**

- **T1547 (Boot or Logon Autostart Execution):** This is the primary tactic for using startup locations for persistence.

---

### ⏰ Scheduled Tasks

**🧾 Summary**

This section lists tasks that are scheduled to run at a specific time, on a recurring basis, or in response to a specific system event (e.g., user logon).

**⚠️ Why This Matters**

Scheduled Tasks are a powerful and stealthy persistence mechanism favored by advanced attackers. They allow malware to execute periodically without needing to be constantly running in memory.

**🔍 What to Look For**

- **Suspicious Task Names:** Look for tasks with vague or randomly generated names.
- **Unusual Actions/Commands:** The action of the task should be scrutinized. A task that runs `powershell.exe` with a Base64-encoded command is a classic indicator of compromise.
- **Tasks Running with High Privileges:** Check what user account the task is configured to run as. Tasks running as `SYSTEM` or `Administrator` are high-risk.
- **Trigger Events:** A task triggered by a common event like "User Logon" is a simple way for malware to re-establish itself.
- **Examine `Last Run Time` and `Last Task Result`:** A result code other than `0` indicates an error, which could be worth investigating. A task that has never run or has a very old run time might also be suspicious.

**🎯 MITRE ATT&CK Mapping**

- **T1053.005 (Scheduled Task/Job: Scheduled Task):** Directly maps to the use of Scheduled Tasks for execution and persistence.

---

### ⚙️ Services

**🧾 Summary**

This section lists system services, their status (Running, Stopped), and their start type (Automatic, Manual, Disabled).

**⚠️ Why This Matters**

Services are programs that run in the background, often without any user interface, and typically start when the OS boots. Attackers create malicious services to gain persistence and run their code with high privileges (often as `LOCAL SYSTEM`).

**🔍 What to Look For**

- **Suspicious Service Names and Descriptions:** Look for services with no description, a nonsensical name, or a description that doesn't match the service's executable.
- **Anomalous `StartType`:** A service that is critical to the OS but is `Disabled` is a red flag. Conversely, a service set to `Automatic` that you don't recognize should be investigated.
- **Executable Path:** The path to the service executable is a crucial field. It should point to a trusted location. An executable path pointing to a temp directory or user folder is highly suspicious.
- **Unsigned Service Executables:** Similar to processes, the underlying executable for a service should be digitally signed by a trusted vendor.

**🎯 MITre ATT&CK Mapping**

- **T1543.003 (Create or Modify System Process: Windows Service):** Attackers create malicious services to persist on a system.

---

###  registry persistence

**🧾 Summary**

This section checks common persistence locations within the Windows Registry, such as `Run`, `RunOnce`, and `RunOnceEx`.

**⚠️ Why This Matters**

These registry keys are "go-to" locations for malware to establish simple persistence. Anything listed in these keys will be executed automatically during system startup or user logon.

**🔍 What to Look For**

- **Direct Executable Paths:** Look for paths to unknown executables, especially those in temporary or user-specific directories.
- **Script Execution:** Be wary of entries that call `rundll32.exe`, `mshta.exe`, or script interpreters like `wscript.exe`. These are often used to launch malicious scripts.
- **Commands in `RunOnce`:** While `Run` is for durable persistence, `RunOnce` is often used by legitimate installers for cleanup. However, malware can use it to execute a payload and then delete itself to reduce its footprint.
- **Empty Keys:** While `RunOnceEx` is rarely used, the fact that it is checked is important. An empty key is the expected finding. Any value found should be treated with extreme suspicion.
