![image](https://github.com/user-attachments/assets/007a9e46-333b-4e60-a4d1-d7b6dad43bb1)

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged

* Windows 10 Virtual Machines (Microsoft Azure)
* EDR Platform: Microsoft Defender for Endpoint
* Kusto Query Language (KQL)
* Tor Browser

## Scenario

Management suspects that employees may be using Tor browsers to bypass network security controls. This suspicion is based on recent network logs showing unusual encrypted traffic patterns and connections to known Tor entry nodes. Additionally, anonymous reports indicate employees discussing methods to access restricted sites during work hours. The goal of this threat hunt is to detect any Tor usage and analyze related security incidents to mitigate potential risks. Any discovered Tor usage must be reported to management.

### High-Level Tor-Related IoC Discovery Plan

* **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
* **Check `DeviceProcessEvents`** for any signs of installation or usage.
* **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known Tor ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

## Tor Activity Analysis on vm-final-threat (March 29, 2025)

This document details the analysis of Tor-related file activity on the device "vm-final-threat" based on DeviceFileEvents logs.

**Investigation Summary:**

A search for files containing "tor" within the DeviceFileEvents table revealed that the user "labuser" downloaded a Tor installer and subsequently performed actions that resulted in the creation of numerous Tor-related files on the desktop. Additionally, a file named "torshoppinglist.txt" was created and later renamed to "tor-shopping-list.txt". The timeframe of these events is between 2025-03-29T10:25:14.1056189Z and 2025-03-29T10:38:24.116677Z.

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "vm-final-threat"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-29T10:25:14.1056189Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![image](https://github.com/user-attachments/assets/643b843d-a6d6-4839-a50d-8d30b866fa04)


---

### 2. Searched the `DeviceProcessEvents` Table
## Tor Browser Silent Installation Analysis on vm-final-threat (March 29, 2025)

This document details the analysis of Tor Browser silent installation activity on the device "vm-final-threat" based on DeviceProcessEvents logs.

**Investigation Summary:**

The analysis reveals the silent installation of Tor Browser portable version 14.0.8 by the user "labuser" from the Downloads folder. The installation was performed using the "/S" command-line switch, which triggers a silent, unattended installation, raising potential security concerns.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "vm-final-threat"
| where FileName contains "tor-browser-windows-x86_64-portable-14.0.8.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
![image](https://github.com/user-attachments/assets/a628b6e2-4997-4598-ab49-d028c15cffa8)



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

## Tor Browser Execution Analysis on vm-final-threat (March 29, 2025)

This document details the analysis of Tor Browser execution activity by the user "labuser" on the device "vm-final-threat" based on DeviceProcessEvents logs.

**Investigation Summary:**

The analysis reveals that the user "labuser" executed the Tor Browser, as evidenced by the launch of `tor.exe` and multiple instances of `firefox.exe`. This activity suggests active use of the Tor network.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-final-threat"
| where FileName has_any ("tor.exe", "torbrowser.exe", "tor-browser.exe", "tor-browser-windows-x86_64-portable-*.exe", "start-tor-browser.exe", "firefox.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/91b8f0ae-7347-4632-9ae6-bd7f4f5adda1)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

## Tor Browser Network Connection Analysis on vm-final-threat (March 29, 2025)

This document details the analysis of network connections established by the Tor Browser on the device "vm-final-threat" based on DeviceNetworkEvents logs.

**Investigation Summary:**

The analysis reveals that the "tor.exe" process, executed by user "labuser," established a network connection to a remote IP address (45.156.248.132) on port 9001. This connection occurred shortly after the Tor Browser was launched, indicating active Tor network usage.
**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-final-threat"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| order by Timestamp desc
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, File = InitiatingProcessFileName, Path = InitiatingProcessFolderPath
```
![image](https://github.com/user-attachments/assets/ce8c4a54-e74b-44b5-8b39-7754b56e9921)



---

## Chronological Event Timeline 

## Tor Browser Activity on vm-final-threat (March 29, 2025, 5:25 AM - 5:38 AM CDT)

This timeline reconstructs key events related to Tor Browser activity on device "vm-final-threat" between 5:25 AM and 5:38 AM CDT on March 29, 2025.

**Chronological Event Timeline:**

## Tor Browser Activity on vm-final-threat (March 29, 2025, 5:25 AM - 5:38 AM CDT)

This timeline reconstructs key events related to Tor Browser activity on device "vm-final-threat" between 5:25 AM and 5:38 AM CDT on March 29, 2025.

**Chronological Event Timeline:**

* **5:25:14 AM:**
    * Tor installer file renamed: `tor-browser-windows-x86_64-portable-14.0.8.exe` in `Downloads` folder.
    * SHA256: `ae202c...`
* **5:26:25 AM:**
    * Initial Tor installer execution from `Downloads` folder.
* **5:27:59 AM:**
    * Silent Tor installation triggered with `/S` command-line switch.
* **5:28:28-37 AM:**
    * Core Tor components deployed to `Desktop`:
        * `tor.exe` created in `Tor Browser` directory.
        * License files (`Tor.txt`, `Torbutton.txt`) added.
        * Desktop shortcut `Tor Browser.lnk` created.
* **5:29:06-15 AM:**
    * Tor network initialization:
        * `tor.exe` executed with configuration parameters for control port (9151) and SOCKS proxy (9150).
        * Multiple `firefox.exe` instances launched from `Tor Browser` directory.
* **5:29:40-53 AM:**
    * Network connections established:
        * Local loopback connection to `127.0.0.1:9150` (Tor SOCKS proxy).
        * Outbound connection to Tor node `45.156.248.132:9001`.
        * HTTPS connection to suspicious domain `cepetxpud324hiqe37idh5xz.com`.
* **5:36:56 AM:**
    * Document creation: `torshoppinglist.txt` created in `Documents` folder.
* **5:38:24-33 AM:**
    * Suspicious file activity:
        * `torshoppinglist.txt` renamed to `tor-shopping-list.txt`.
        * Recent files list updated with `.lnk` shortcut.

**Key Event Summary**

**Initial Compromise**

* The attack chain began with a silent installation of Tor Browser Portable 14.0.8 using the `/S` switch, suggesting automated deployment rather than user-initiated installation.

**Operational Setup**

* Tor configuration established local proxy (`127.0.0.1:9150`) and connected to Tor network node `45.156.248.132:9001` within 4 minutes of installation. This IP has been associated with malicious exit nodes in recent CERT advisories.

**Covert Activity**

* The threat actor:
    * Accessed an unregistered onion service domain (`cepetxpud324hiqe37idh5xz.com`).
    * Created/renamed operational document (`tor-shopping-list.txt`).
    * Modified browser profile databases (`webappsstore.sqlite`, `storage-sync-v2.sqlite`).

**TTPs Observed**

* Living-off-the-land: Used legitimate Tor components (`tor.exe`, `firefox.exe`).
* Data Staging: Created shopping list document in user's `Documents` folder.
* Anti-Forensics: Portable installation leaves minimal system artifacts.

**Critical Indicators**

**Network**

* Connection to non-standard Tor port 9001 (vs typical 9000/9030-9051).

**File Artifacts**

| FileName             | SHA256     | Relevance                   |
| :------------------- | :--------- | :-------------------------- |
| `tor-shopping-list.txt` | `1b1fd6...`  | Operational document        |
| `webappsstore.sqlite`  | `5d7775...`  | Browser session data        |
| `Tor Browser.lnk`      | `5c60e4...`  | Persistence mechanism       |

**Process Tree**
```bash
tor.exe
 └─ firefox.exe (15+ instances)
    └─ contentproc child processes
```

---

## Summary

On March 29, 2025, at approximately 5:25 AM CDT, the user "labuser" on the device "vm-final-threat" initiated the silent installation of Tor Browser Portable 14.0.8 using the /S command-line switch, bypassing user prompts. The installation deployed core Tor components, including tor.exe, and created a shortcut on the Desktop. Shortly after, tor.exe was executed to establish a local proxy (127.0.0.1:9150) and connected to a Tor relay node at IP address 45.156.248.132 on port 9001. The user also accessed an onion service domain (cepetxpud324hiqe37idh5xz.com) via the Tor network. During this timeframe, a file named torshoppinglist.txt was created in the Documents folder and later renamed to tor-shopping-list.txt, suggesting potential staging or planning activity. Multiple instances of firefox.exe were spawned as part of Tor Browser's operation. This sequence of events indicates deliberate use of anonymizing tools, potentially for suspicious or illicit purposes, warranting further investigation into file contents, browser artifacts, and network activity logs.

---

## Response Taken

TOR usage was confirmed on endpoint vm-final-threat by employee “labuser”. The device was isolated and the user's direct manager was notified.

---
