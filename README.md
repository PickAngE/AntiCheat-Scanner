# Anti-Cheat Scanner

## Description
Forensic tool for Windows environments designed to identify the active presence and execution traces of anti-cheat software. The script performs multi-layered analysis across User-mode, Kernel-mode, Registry, and File System.

## Detection Targets
- ACE (AntiCheatExpert)
- Vanguard (Riot Games)
- Ricochet (Activision)
- EA Anti-Cheat / Javelin
- EAC (EasyAntiCheat)
- BattlEye
- HoYoProtect (mhyprot)

## Inspection Points (16 Subsystems)
- **Processes & Services**: Analysis via WMI and Service Control Manager.
- **File System**: Scans files, folders, and directory segments.
- **PE Metadata**: Validation of ProductName, CompanyName, and OriginalFilename.
- **Authenticode**: Digital certificate verification for drivers (.sys) and executables (.exe).
- **Registry**: Analysis of installation, persistence, and service keys.
- **BCD**: Early Launch Boot Configuration Data inspection.
- **BAM (Background Activity Moderator)**: System execution history logs.
- **AppCompatFlags**: Windows Compatibility Assistant traces.
- **MUICache**: Explorer execution history.
- **Scheduled Tasks**: Analysis of execution triggers and rules.
- **Prefetch (.pf)**: Windows preloading file analysis.
- **Security**: Windows Defender exclusions and inbound Firewall rules.
- **Named Pipes**: IPC channel analysis (`\\.\pipe\`).
- **Minifilter**: Kernel-mode filter driver instances (`fltmc`).
- **Network**: Active connections (`netstat`) and DNS resolvers.
- **DNS Cache**: Domain name resolution traces related to anti-cheat servers.

## Security & Integrity
- **Windows Whitelist**: Automatic exclusion of critical system processes (`services.exe`, `lsass.exe`, etc.).
- **Technical Isolation**: Structured reports separating functional detections from deep binary analysis (SHA256).

## Installation
1. Clone the repository:
   ```powershell
   git clone https://github.com/PickAngE/AntiCheat-Scanner.git
   ```
2. Navigate to the project folder:
   ```powershell
   cd AntiCheat-Scanner
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

## Usage
```powershell
python main.py
```

## License
Proprietary. Copyright (c) 2026 PickAngE.
- Commercial use prohibited.
- Redistribution and modification prohibited.
- Software provided "AS IS" without liability for system stability or account status.
