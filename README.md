# Anti-Cheat Scanner

A Windows forensic utility that detects the presence, configuration, and execution traces of anti-cheat software through multi-layer system analysis.

## Supported Targets

- ACE (AntiCheatExpert)
- EA Anti-Cheat / Javelin
- EAC (EasyAntiCheat)
- BattlEye
- HoYoProtect (mhyprot)

## Detection Methods

The scanner collects evidence across the following subsystems:

**Kernel & Drivers**
- Minifilter driver enumeration via Windows Filter Manager (`fltmc`)
- Loaded kernel module listing via DriverQuery
- WMI system driver cross-reference against vendor signatures

**Processes & Services**
- Service Control Manager (SCM) database query for registered anti-cheat services
- Active process and loaded module analysis with signature matching, fuzzy matching, and metadata fallback

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

## Architecture

All detection subsystems inherit from a common `BaseChecker` interface and return standardized `Detection` dataclass objects. An optimized O(1) signature index is used for high-volume matching. Checkers are registered in `checkers/registry.py` and run in parallel via `ThreadPoolExecutor`.

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

```powershell
python main.py
```

The script automatically requests elevation via UAC when not running as administrator. If elevation is denied, the scan continues with limited coverage.

Options:

| Flag | Description |
|---|---|
| `--no-pause` | Exit immediately after scan (useful for automation/CI) |
| `--quiet`   | Suppress debug output; show only warnings and errors |
| `--output PATH` | Report file or directory for the text report |
| `--json`    | Also write a JSON report alongside the text report |
| `--workers N` | Maximum parallel checker workers (default: 4) |

### Output

Results are written to an `AntiCheat_Report_<timestamp>.txt` file, including detected software, matched signatures, and subsystem findings. With `--json`, a machine-readable `.json` report is also generated with the same data structured by anti-cheat product and category.

## Technical Notes

- **Automatic privilege elevation**: Requests Administrator privileges via UAC when detected as non-admin, with a silent fallback to limited coverage if denied.
- **Standardized detection format**: All checkers return `Detection` dataclass objects with uniform fields (`category`, `text`, `ac_name`, `active`, `raw`, `tech`), consumed by a single report builder.
- **Parallel execution**: Checkers run concurrently via `ThreadPoolExecutor` (configurable with `--workers`).
- **Multi-layer matching**: Exact signature match through O(1) index, fuzzy name matching via rapidfuzz, and metadata-based detection (CompanyName, ProductName, digital certificate subject).
- **External signature database**: Anti-cheat signatures are loaded from `config/signatures.json`.
- **Optimized signature indexing**: Builds an O(1) lookup index from the signature database for high-volume string matching across all subsystems.
- **Batched Authenticode verification**: Digital signatures are verified in a single PowerShell invocation per batch to minimize process overhead.
- **Segment-based path matching**: Filesystem scans use folder segment matching to reduce false positives.

## Disclaimer

This tool is intended for forensic analysis, system auditing, and educational purposes only. Detection results are based on heuristic indicators and historical artifacts; they may contain false positives or miss obfuscated or unknown anti-cheat implementations. Always cross-validate findings with additional forensic tools.

## License

Proprietary. See [LICENSE](LICENSE) for full terms.
