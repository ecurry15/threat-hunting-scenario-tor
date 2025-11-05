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

">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

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

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
