<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ecurry15/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents table` for any file that had the string “tor” in it. Discovered that the user downloaded a Tor installer, generated activity that created Tor-related files, created a file called tor-shopping-list.txt, and then later deleted the Tor browser and its related files. These events began at this time: `2025-11-03T02:57:40.1684141Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName contains "Ecurry-ThreatHu"
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1872" height="809" alt="image" src="https://github.com/user-attachments/assets/7a5383a5-7daf-4799-a1df-99f73425b9df" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for activity that included the file name `"tor-browser-windows-x86_64"`. Based on the logs returned at `2025-11-03T02:58:19.7881619Z`, a user used the command line to run `“tor-browser-windows-x86_64-portable-15.0.exe /S”` from their downloads folder.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "Ecurry-ThreatHu"
| where FileName contains "tor-browser-windows-x86_64"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName

```
<img width="1906" height="319" alt="image" src="https://github.com/user-attachments/assets/1f9860aa-29a1-4c5a-84c7-605d287fbc64" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any evidence that the user actually used the Tor browser. There was evidence found that the browser was opened, starting at `2025-11-03T03:02:48.1472833Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "Ecurry-ThreatHu"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```
<img width="1888" height="918" alt="image" src="https://github.com/user-attachments/assets/a00b3840-ecd7-40f6-a137-eabb2f1107ea" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any evidence that the user searched for content on the Tor Browser. After filtering for known Tor Browser ports, evidence was found that the user established a successful connection to the remote IP address `150.136.142.129` on `port 9001` at `2025-11-03T03:03:25.1090638Z`. The connection was initiated by the process `tor.exe`, in file path: `c:\users\ecurry3015\desktop\tor browser\browser\torbrowser\tor\tor.exe`. Other logs were found that included web URLs that the user visited. `https://www[.]d4ayzdzictqww[.]com` and `https://www[.]xhgumv4z[.]com`


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "Ecurry-ThreatHu"
| order by Timestamp desc 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
```
<img width="1903" height="558" alt="image" src="https://github.com/user-attachments/assets/42f646f9-cad9-4de9-b26d-c2593e17c011" />


---

## Chronological Event Timeline 

### 1. User downloaded the Tor installer and created related files

- File activity showed Tor-related files being generated, including “tor-shopping-list.txt.”
- The user later deleted the Tor browser and associated files.
- **Time:** 2025-11-03T02:57:40.1684141Z
- **Source:** DeviceFileEvents — search for files starting with “tor”

### 2. User executed the Tor Browser installer via the command line

- **Command run:** tor-browser-windows-x86_64-portable-15.0.exe /S
- Executed from the Downloads folder.
- **Time:** 2025-11-03T02:58:19.7881619Z
- **Source:** DeviceProcessEvents — search for “tor-browser-windows-x86_64”

### 3. User launched the Tor Browser

- Evidence confirmed that tor.exe / firefox.exe / tor-browser.exe processes were initiated.
- **Time:** 2025-11-03T03:02:48.1472833Z
- **Source:** DeviceProcessEvents — search for Tor-related executables
- **File Path:** `c:\users\ecurry3015\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. User established a network connection through the Tor Browser

- Process tor.exe connected to remote IP `150.136.142.129` on `port 9001`.
- **Time:** 2025-11-03T03:03:25.1090638Z
- Logs also indicated visits to: `https://www[.]d4ayzdzictqww[.]com` and `https://www[.]xhgumv4z[.]com`
- **Process:** `tor.exe`
- **Source:** DeviceNetworkEvents — filtered for Tor-related ports 9001–9150
- **File Path:** `c:\users\ecurry3015\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation - TOR Shopping List
- The user created a file named `tor-shopping-list.txt`, potentially indicating a list or notes related to their TOR browser activities.
- **Time:** `2025-11-03T03:15:08.9996518Z`
- **Action:** File creation.
- **File Path:** `C:\Users\ecurry3015\Documents\tor-shopping-list.txt`


### 6. File/browser deletion.

- The user attempted to erase evidence by deleting the Tor browser and its generated files, including the shopping list.
- **Time:** `2025-11-03T03:16:17.6984709Z`
- **Action:** File deletion.
- **Source:** DeviceFileEvents — filter for files that include "tor”
---

## Summary

An investigation into device Ecurry-ThreatHu revealed that a user downloaded, installed, and briefly used the Tor Browser before deleting it. File activity began at 2025-11-03T02:57:40Z, when the user downloaded a Tor installer and created related files, including one named “tor-shopping-list.txt.” Shortly afterward, at 02:58:19Z, the user ran the Tor Browser installer from the command line, confirming a deliberate installation.

At 03:02:48Z, logs showed that the Tor Browser was launched, and less than a minute later, at 03:03:25Z, the process tor.exe established a successful outbound network connection to 150.136.142.129 on port 9001, consistent with Tor network traffic. Additional evidence showed visits to hidden service URLs. Following this activity, the user deleted the Tor Browser and its associated files, indicating an attempt to remove traces of use.


---

## Response Taken

TOR usage was confirmed on endpoint `Ecurry-ThreatHunt-Lab`. The device was isolated, and the user's direct manager was notified.

---
