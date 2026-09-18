<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TeShawnYoung/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks like the user  “Ty” downloaded a tor installer and created a file called “tor-shopping-list.lnk” on the desktop. These even began at 2026-08-01T04:46:25.1751224Z
Query used to locate events: 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ty-threat-hunt"
| where FileName contains "tor"
| order by Timestamp desc
| where InitiatingProcessAccountName == "ty"
| where TimeGenerated >= datetime(2026-08-01T04:44:33.5452372Z)
| project Timestamp, DeviceName, ActionType, FileName, SHA256, InitiatingProcessAccountName, FolderPath

```
<img width="938" height="590" alt="image" src="https://github.com/user-attachments/assets/039e6ba4-5319-4791-82f3-108e933f27e5" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.19.exe /s”. Based on the logs returned, at 12:46 AM on August 1, 2026, the user Ty ran a silent installation of the Tor Browser Portable installer from the Downloads folder on the device ty-threat-hunt, creating a new process without displaying the normal installation prompts. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ty-threat-hunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"
| project Timestamp, FolderPath, ProcessCommandLine, ActionType, DeviceName, AccountName

```
<img width="941" height="140" alt="image" src="https://github.com/user-attachments/assets/d5b758f5-b995-4ada-b49a-521a5f80453c" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “Ty” actually opened the browser. There was evidence that they did open it at 2026-08-01T04:46:41.1669409Z

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "ty-threat-hunt"
| where FileName has_any ("tor.exe","firefox.exe")
| order by Timestamp desc
| project TimeGenerated, DeviceName, AccountName, ActionType,FileName, ProcessCommandLine


<img width="948" height="825" alt="image" src="https://github.com/user-attachments/assets/db05d63a-28eb-4133-98b8-c5a86d9b48a1" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. On 2026-08-01T04:47:25.7866807Z, the user account "ty" successfully established a network connection using Firefox located inside the Tor Browser folder (C:\Users\ty\Desktop\Tor Browser\Browser\firefox.exe). The browser connected to the local IP address 127.0.0.1 on port 9150, which is the default Tor SOCKS proxy port. This indicates that the Tor Browser was successfully communicating with its local Tor service to route network traffic through the Tor network. There many connections using port 443 to browse sites. 

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "ty-threat-hunt"
| project Timestamp, ActionType, DeviceName,  InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| where InitiatingProcessAccountName != "system"
| order by Timestamp desc
| where RemotePort in ("9001","9030","9050","9150","80","443")

---

## Chronological Event Timeline 

## Tor Browser Threat Hunt Timeline

### 1. File Download – Tor Browser Installer

* **Timestamp:** `2026-08-01T04:44:33Z` (12:44:33 AM)
* **Event:** The user **"ty"** downloaded the Tor Browser Portable installer to the Downloads folder.
* **Action:** `FileRenamed`
* **File:** `tor-browser-windows-x86_64-portable-15.0.19.exe`
* **File Path:** `C:\Users\Ty\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

---

### 2. File Creation – Tor Browser Installer

* **Timestamp:** `2026-08-01T04:44:38Z` (12:44:38 AM)
* **Event:** The Tor Browser installer finished writing to disk, making it available for execution.
* **Action:** `FileCreated`
* **File:** `tor-browser-windows-x86_64-portable-15.0.19.exe`
* **File Path:** `C:\Users\Ty\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

---

### 3. Process Execution – Tor Browser Installation

* **Timestamp:** `2026-08-01T04:46:04Z` (12:46:04 AM)
* **Event:** The user **"ty"** executed the Tor Browser Portable installer in silent mode, initiating a background installation without displaying the installation wizard.
* **Action:** `ProcessCreated`
* **Command:** `tor-browser-windows-x86_64-portable-15.0.19.exe /S`
* **Account:** `ty`
* **Device:** `ty-threat-hunt`
* **File Path:** `C:\Users\Ty\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

---

### 4. File Deletion – Tor Browser Installer

* **Timestamp:** `2026-08-01T04:46:42Z` *(or the timestamp reflected in your logs)*
* **Event:** The Tor Browser installer was deleted after installation completed.
* **Action:** `FileDeleted`
* **File:** `tor-browser-windows-x86_64-portable-15.0.19.exe`
* **File Path:** `C:\Users\Ty\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`

---

### 5. File Creation – Tor Browser Application Files

* **Timestamp:** `2026-08-01T04:46:25Z` (12:46:25 AM)
* **Event:** Installation created numerous Tor Browser application files within the installation directory, confirming the software was successfully installed.
* **Action:** Multiple `FileCreated` events detected.
* **Examples:**

  * `tor.exe`
  * `tor.txt`
  * `Torbutton.txt`
  * `Tor-Launcher.txt`
* **File Path:** `C:\Users\Ty\Desktop\Tor Browser\`

---

### 6. File Creation – Tor Browser Shortcuts

* **Timestamp:** `2026-08-01T04:46:31Z` (12:46:31 AM)
* **Event:** Installation created desktop and Start Menu shortcuts for the Tor Browser, indicating installation completed successfully.
* **Action:** `FileCreated`
* **Files:**

  * `Tor Browser.lnk`
  * Desktop shortcut
  * Start Menu shortcut

---

### 7. Process Execution – Tor Browser Launch

* **Timestamp:** `2026-08-01T04:46:41Z` (12:46:41 AM)
* **Event:** The user **"ty"** launched the Tor Browser. Multiple **firefox.exe** processes were created from the Tor Browser installation directory, confirming the browser started successfully.
* **Action:** `ProcessCreated`
* **Processes:** `firefox.exe`, `tor.exe`
* **File Path:** `C:\Users\Ty\Desktop\Tor Browser\Browser\`

---

### 8. File Creation – Browser Profile Initialization

* **Timestamp:** `2026-08-01T04:46:54Z – 04:46:56Z`
* **Event:** During the browser's first launch, Tor Browser created its initial browser profile databases and configuration files.
* **Action:** Multiple `FileCreated` events detected.
* **Examples:**

  * `storage.sqlite`
  * `storage-sync-v2.sqlite`
  * `webappsstore.sqlite`

---

### 9. Network Connection – Local Tor Proxy

* **Timestamp:** `2026-08-01T04:47:25Z` (12:47:25 AM)
* **Event:** Firefox running from the Tor Browser installation directory established a connection to the local Tor SOCKS proxy.
* **Action:** `ConnectionSuccess`
* **Process:** `firefox.exe`
* **Remote IP:** `127.0.0.1`
* **Remote Port:** `9150`
* **File Path:** `C:\Users\Ty\Desktop\Tor Browser\Browser\firefox.exe`

---

### 10. Network Connections – Tor Browser Web Activity

* **Timestamp:** `Beginning 2026-08-01T04:47:26Z`
* **Event:** Following successful communication with the local Tor proxy, the browser established numerous outbound HTTPS connections over port **443**, consistent with normal web browsing through the Tor network.
* **Action:** Multiple `ConnectionSuccess` events detected.
* **Ports:** `443`
* **Process:** `firefox.exe`

---

### 11. File Creation – Tor Shopping List

* **Timestamp:** `2026-08-01T05:45:56Z` (1:45:56 AM)
* **Event:** The user **"ty"** created a file named **tor-shopping-list.txt**. A corresponding shortcut was also created in the user's **Recent Items** folder, indicating the document was later opened or accessed.
* **Action:** `FileCreated`
* **Files:**

  * `tor-shopping-list.txt`
  * `tor-shopping-list.lnk`
* **File Path:** `C:\Users\Ty\Desktop\tor-shopping-list.txt`


---

## Summary

The investigation confirmed that user Ty successfully installed, launched, and used the Tor Browser on the device ty-threat-hunt.

The evidence shows the following sequence of events:

* The Tor Browser Portable installer was executed silently from the user's Downloads folder.
* Tor-related files were created on the system, indicating a successful installation.
* The user launched the Tor Browser, resulting in multiple Firefox processes running from the Tor Browser installation directory.
* The browser successfully connected to the local Tor SOCKS proxy using 127.0.0.1:9150, confirming communication with the local Tor service.
* Immediately afterward, encrypted outbound HTTPS traffic was observed, indicating that browser activity was routed through the Tor network.


---

## Response Taken

TOR usage was confirmed on endpoint ty-threat-hunt. The device was isolated and the user's direct manager was notified.


---
