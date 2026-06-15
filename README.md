# Anti-Cheat Scanner

A Windows forensic utility that detects the presence, configuration, and execution traces of anti-cheat software through multi-layer system analysis.

## Detection Methods

The scanner collects evidence across the following subsystems:

**Kernel & Drivers**
- Minifilter driver enumeration via Windows Filter Manager (`fltmc`)
- Loaded kernel module listing via DriverQuery
- WMI system driver cross-reference against vendor signatures

**Processes & Services**
- Service Control Manager (SCM) database query for registered anti-cheat services
- Active process and loaded module analysis with signature matching

**File System & Binary Forensics**
- Authenticode digital signature verification (batched via PowerShell)
- PE metadata extraction (CompanyName, ProductName, etc.)
- SHA256 hashing for binary identification

**Execution Artifacts**
- BAM (Background Activity Moderator) per-user SID analysis
- AppCompatFlags execution history (Compatibility Assistant)
- Shell MuiCache scan
- Prefetch file parsing

**Registry Forensics**
- Installation keys and persistence mechanism analysis
- WOW6432Node cross-architecture scanning
- App Paths and Uninstall key inspection

**Network & IPC**
- Named pipe namespace scan (`\\.\pipe\`)
- DNS resolver cache inspection
- Active connection enumeration via `netstat`

**System Configuration**
- BCD (Boot Configuration Data) boot entry and kernel flag checks
- Scheduled task enumeration
- Windows Defender exclusion and Firewall rule review

## Supported Targets

- ACE (AntiCheatExpert)
- EA Anti-Cheat / Javelin
- EAC (EasyAntiCheat)
- BattlEye
- HoYoProtect (mhyprot)

## Architecture

All detection subsystems inherit from a common `BaseChecker` interface and share an optimized O(1) signature index for high-volume matching. The scanner runs checkers in parallel (up to 4 concurrent workers) and aggregates findings into a unified report.

| Checker | Coverage |
|---|---|
| `ServiceChecker` | SCM-registered anti-cheat services |
| `ProcessChecker` | Running processes and loaded modules |
| `DriverFileChecker` | Kernel-mode driver files |
| `FileChecker` | Filesystem binary artifacts |
| `RegistryChecker` | Registry keys and values |
| `TaskChecker` | Scheduled tasks |
| `TraceChecker` | Execution artifacts (BAM, Prefetch, MUICache, etc.) |

## Requirements

- Windows 10 / 11 (x64)
- Python 3.10+
- Administrator privileges (recommended for full coverage)

## Dependencies

| Package | Version |
|---|---|
| `psutil` | >=5.9, <7 |
| `pywin32` | >=306, <400 |
| `rapidfuzz` | >=3.0, <4 |

## Installation

```powershell
git clone https://github.com/PickAngE/Anti-Cheat-Scanner.git
cd Anti-Cheat-Scanner
pip install -r requirements.txt
```

## Usage

Run with administrator privileges:

```powershell
python main.py
```

The script will automatically prompt for elevation via UAC if not already running as admin.

Options:

| Flag | Description |
|---|---|
| `--no-pause` | Exit immediately after scan (useful for automation/CI) |
| `--quiet`   | Suppress debug output; show only warnings and errors |

### Output

Results are written to an `AntiCheat_Report_<timestamp>.txt` file in the project directory, including detected software, matched signatures, and subsystem findings.

### Tests

```powershell
python -m unittest discover -s tests
```

## Technical Notes

- **Automatic privilege elevation**: Requests Administrator privileges via UAC when detected as non-admin, with an option to continue with limited coverage.
- **Parallel execution**: Checkers run concurrently via `ThreadPoolExecutor` (up to 4 workers) to reduce scan time.
- **Optimized signature indexing**: Builds an O(1) lookup index from the signature database for high-volume string matching across all subsystems.
- **Batched Authenticode verification**: Digital signatures are verified in a single PowerShell invocation per batch to minimize process overhead.
- **Segment-based path matching**: Filesystem scans use folder segment matching to reduce false positives.

## Disclaimer

This tool is intended for forensic analysis, system auditing, and educational purposes only. Detection results are based on heuristic indicators and historical artifacts; they may contain false positives or miss obfuscated or unknown anti-cheat implementations. Always cross-validate findings with additional forensic tools.

## License

Proprietary. See [LICENSE](LICENSE) for full terms.
