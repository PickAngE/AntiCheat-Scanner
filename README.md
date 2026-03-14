# Anti-Cheat Scanner

## Description

The Anti-Cheat Scanner is an automated forensic analysis tool intended for Windows environments to identify execution artifacts and active presence of known anti-cheat software software.

This tool conducts deep inspections in the user-mode registry, file system, network layer, and caching histories to construct an execution log.

## Features and Capabilities

The script identifies the following targets:
- ACE (AntiCheatExpert)
- Vanguard (Valorant / League of Legends / VGK)
- Ricochet (Call of Duty)
- EA Javelin / EA Anti-Cheat
- EAC (EasyAntiCheat)
- BattlEye
- HoYoProtect (mhyprot)

The scanner executes inspections across 16 subsystems and traces:
- Running Processes and Services (WMI, Service Control Manager)
- Local Files, Folders, and Directories
- PE Header Metadata Validation (ProductName, CompanyName)
- Digital Certificate Authenticode Chains for Loaded/Unloaded Drivers (`.sys`)
- Installation and Uninstallation Registries
- Early Launch Boot Configuration Data (BCD)
- Background Activity Moderator (BAM) Registries
- Windows Compatibility Assistant Histories (AppCompatFlags / Store)
- Explorer MUICache Histories
- Task Scheduler Items and Execution Rules
- Prefetch (`.pf`) Histories
- Windows Defender Exclusions & Inbound Firewall Rules
- Named IPC Pipes (`\\.\pipe\`)
- Kernel-mode Minifilter Instances (`fltmc`)
- Active Network Connections and Listeners (`netstat`)
- DNS Cache Traces

## Requirements

- Python 3.8 or higher.
- Windows 10 or 11 (NT architecture).
- Administrator (Elevated) privileges required for registry and driver extraction.

## Installation

1. Clone or download the repository.
   ```
   git clone https://github.com/PickAngE/Anti-Cheat-Scanner.git
   ```
2. Change into the directory.
   ```
   cd Anti-Cheat-Scanner
   ```
3. Install Python dependencies.
   ```
   pip install -r requirements.txt
   ```

## Usage

Execute the entry-point script with Python. Ensure you run this from an administrator prompt. If executed in standard mode, the script attempts to elevate via UAC.

```
python main.py
```

The application provides real-time progress updates in the console during the scan.
Upon completion, a comprehensive forensic report is generated in the working directory, structured as `AntiCheat_Report_YYYYMMDD_HHMMSS.txt`.

## License and Terms of Use

This software is governed by a **PROPRIETARY SOFTWARE LICENSE AGREEMENT**.
Copyright (c) 2026 PickAngE.

**STRICT RESTRICTIONS APPLY:**
- No commercial use.
- No modifications, adaptations, or reverse engineering.
- No redistribution, public hosting, sublicensing, or forks.
- Retains all ownership of source code by Licensor.

**DISCLAIMER OF LIABILITY:**
The Licensor provides the software "AS IS". Execution is strictly at the user's voluntary discretion and risk. 
The Licensor is completely indemnified and assumes no liability for operating system instability, hardware damages, bans, or account suspensions directly or indirectly resulting from the utilization of this scanner. 

Please read the complete [LICENSE](LICENSE) text prior to execution. Violation of license terms terminates authorization immediately.
