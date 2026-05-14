# Anti-Cheat Scanner

## Overview

Anti-Cheat Scanner is a forensic utility designed for Windows environments to identify the presence, configuration, and execution traces of modern anti‑cheat software.  
It uses a multi‑layer analysis approach, extracting data from kernel‑mode drivers, user‑mode processes, the Windows Registry, and various system forensic artifacts to provide a comprehensive view of the anti‑cheat landscape on a host machine.

## Detection Subsystems

The tool performs deep inspection across the following 16+ subsystems to ensure maximum detection coverage.

### Kernel and Driver Analysis
- **Minifilter Drivers** – Inspects the Windows Filter Manager (`fltmc`) for registered filesystem filter instances used by anti‑cheats for real‑time monitoring and protection.
- **DriverQuery** – Enumerates loaded kernel modules, validating their memory addresses, file paths, and origins.
- **WMI SysDriver** – Cross‑references WMI‑reported system drivers with known vendor signatures.

### Process and Service Monitoring
- **Service Control Manager (SCM)** – Queries the SCM database for registered anti‑cheat services, including stopped, pending, or disabled states.
- **Process Analysis** – Monitors active process trees via WMI and native APIs, validating executables against a known signature database.

### File System and Binary Forensics
- **Digital Signature Validation (Authenticode)** – Verifies the integrity and authenticity of PE files (`.exe`, `.sys`, `.dll`) using Windows Authenticode providers.
- **PE Metadata Inspection** – Extracts and validates `CompanyName`, `ProductName`, and `OriginalFilename` from binary resource sections to detect spoofing or hidden components.
- **SHA256 Hashing** – Generates unique identifiers for critical binaries to cross‑reference against known versions.

### Forensic Execution Artifacts
- **BAM (Background Activity Moderator)** – Analyzes the BAM registry state to identify recently executed binaries and their associated Security Identifiers (SIDs).
- **AppCompatFlags** – Inspects the Windows Compatibility Assistant history for traces of previous anti‑cheat executions.
- **MUICache** – Scans the Shell MuiCache for recorded execution events within Windows Explorer.
- **Prefetch (`.pf`)** – Analyzes the Windows preloading subsystem to identify historical execution patterns and timestamps.

### Registry Forensics
- **Configuration & Persistence** – Analyzes installation keys, persistence mechanisms, and software configuration entries.
- **Architecture Validation** – Scans `WOW6432Node` for 32‑bit software traces on 64‑bit systems to ensure no legacy components are missed.
- **Software Lifecycle** – Inspects `App Paths` and `Uninstall` keys for lingering traces of uninstalled or partially removed software.

### Network and IPC Analysis
- **Named Pipes** – Scans the `\\.\pipe\` namespace for inter‑process communication channels used by anti‑cheat engines.
- **DNS Cache** – Inspects the local DNS resolver cache for lookups related to anti‑cheat backend infrastructure and telemetry servers.
- **Network Connections** – Identifies active network connections or listening ports using `netstat` analysis.

### System Configuration
- **BCD (Boot Configuration Data)** – Checks for "Early Launch" boot entries and specialized kernel‑mode boot flags.
- **Scheduled Tasks** – Identifies background tasks configured for persistence, periodic integrity checks, or stealth updates.
- **Security Policy Exclusions** – Scans Windows Defender exclusions and Firewall inbound rules for vendor‑specific configurations that might bypass standard security protocols.

## Detection Targets

The scanner uses a curated database of signatures for major anti‑cheat solutions, including:

- ACE (AntiCheatExpert)
- Vanguard (Riot Games)
- Ricochet (Activision)
- EA Anti‑Cheat / Javelin
- EAC (EasyAntiCheat)
- BattlEye
- HoYoProtect (mhyprot)

> **Note:** Detection for **Vanguard** and **Ricochet** may not work properly.

## Technical Implementation
- **Automatic Privilege Elevation**: The script detects current permission levels and automatically requests Administrative privileges via UAC when necessary for deep system access.
- **Optimized Signature Indexing**: Implements an O(1) lookup index for efficient matching against high-volume system data, minimizing execution time.
- **Recursive Path Validation**: Performs targeted filesystem scans across common installation paths and user-controlled directories.

## Installation
1. Clone the repository:
   ```powershell
   git clone https://github.com/PickAngE/AntiCheat-Scanner.git
   ```
2. Navigate to the project directory:
   ```powershell
   cd AntiCheat-Scanner
   ```
3. Install the required dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage
Run the main script with administrative privileges:
```powershell
python main.py
```

## Disclaimer
This tool is intended for forensic analysis, system auditing, and educational purposes only. Detection results are based on heuristic indicators and historical artifacts; they may contain false positives or miss sophisticated obfuscation techniques. Always cross-validate findings with additional forensic tools.

## License
Proprietary. Copyright (c) 2026 PickAngE.
- Commercial use prohibited.
- Redistribution and modification prohibited.
- Software provided "AS IS" without warranty of any kind.
