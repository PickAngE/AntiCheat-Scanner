# Anti-Cheat Scanner

Anti-Cheat Scanner is a Windows utility for identifying anti-cheat software, related files, services, drivers, registry entries, and execution traces on a local machine.

## Supported targets

The covered list is fixed; database work only improves entry quality, never the roster.

| Short label | Database `name` |
|---|---|
| ACE / AntiCheatExpert | `ACE (AnticheatExpert)` |
| EA Javelin / EA Anti-Cheat | `EA Javelin` |
| Easy Anti-Cheat | `EAC (EasyAntiCheat)` |
| BattlEye | `BE (BattlEye)` |
| HoYoProtect | `HoYoProtect` |

Note: bare `EAC` (service) / `EAC.sys` (driver) entries belong to **EA Javelin**
(observed component names), even though `EAC` commonly abbreviates
EasyAntiCheat. Corroborate a bare-`EAC` hit with a full `EAAntiCheat*`/`Javelin*`
name before concluding. See `config/signatures.md`.

## Detection areas

### Runtime

- Running processes (name, path, plus command-line corroboration)
- Windows services
- Loaded filter drivers (`fltmc`)
- DriverQuery entries (installed vs running distinguished)
- Network connections and named pipes

### Files and binaries

- Known anti-cheat folders
- File metadata (`.exe`/`.sys`/`.dll`)
- SHA-256 hashes
- Authenticode signer subjects
- Scheduled tasks (including UNC and `%VAR%` paths)
- Prefetch filename indicators (via the task checker)

### Windows artifacts

- Installed services and registry keys (explicit 64/32-bit views)
- Uninstall entries (`DisplayName`, corroborated by `Publisher`/`InstallLocation`)
- Application Paths
- Startup entries
- MuiCache
- AppCompat history
- BAM execution records
- Defender exclusions
- Firewall rules
- DNS cache
- Event log indicators (most recent System records, `--eventlog-limit`)
- Boot configuration text

## What counts as active

An anti-cheat is shown `[ACTIVE]` when at least one detection proves runtime
activity; otherwise `[TRACES]` (installed or historical evidence).

| Category | `active=True` exactly when |
|---|---|
| Processes | process is running |
| Services | SCM status is `running` |
| Filter drivers (`fltmc`) | driver instance is loaded |
| DriverQuery / WMI drivers | reported state is running/started |
| Network | owning connection is `ESTABLISHED`/`LISTENING` |
| Drivers on disk, folders, registry, tasks, prefetch, event log, others | never (evidence of presence/history, not activity) |

Driver files on disk are presence evidence; whether a driver is loaded is
reported separately by the runtime checks above.

Each anti-cheat section also shows an `[Active Evidence]` summary first: it
mirrors every detection proving runtime activity (same items as their home
categories, counted once). In JSON it appears as the `active` list.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- Administrator privileges for complete coverage
- `pywin32` and `psutil` (declared in `pyproject.toml` / `requirements.txt`)

## Installation

```powershell
git clone https://github.com/PickAngE/Anti-Cheat-Scanner.git
cd Anti-Cheat-Scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Or install the package itself (provides the `anti-cheat-scanner` command):

```powershell
python -m pip install .
```

## Usage

A direct interactive launch waits before closing. Use `--no-pause` for automation:

```powershell
.\.venv\Scripts\python.exe .\main.py --no-pause
```

Reports default to the current directory. Use `--output-dir` to select another:

```powershell
python main.py --output-dir C:\Reports --json --no-pause
```

Available options:

```text
--json              Write a JSON report
--workers N         Number of concurrent checkers (default: 5)
--timeout N         Per-checker timeout in seconds (default: 300)
--eventlog-limit N  System event-log records inspected (default: 300)
--max-depth N       Maximum filesystem search depth (default: 1)
--full              Scan configured roots recursively
--include CAT,...   Run only these categories
--exclude CAT,...   Skip these categories (wins over --include)
--list-checkers     List checker classes and exit
--list-ac           List known anti-cheat names and exit
--validate-config   Validate signatures/whitelist and exit
--print-whitelist   Print the active whitelist and exit
--output-dir PATH   Report destination (default: current directory)
--pause             Wait for Enter before exiting (default)
--no-pause          Exit without waiting for Enter
--strict            Return non-zero for a partial scan
--verbose           Enable debug logging
--no-elevate        Skip the admin-elevation check (CI / non-admin runs)
--no-whitelist      Bypass whitelist filtering (audit runs)
--version           Print the version and exit
```

Categories for `--include`/`--exclude`: `services`, `processes`, `drivers`,
`folders`, `registry`, `tasks`, `traces`.

The scanner requests elevation through UAC when needed. A denied, failed, or
timed-out elevation cancels the scan with a non-zero exit code.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished (`complete`, or `partial` without `--strict`) |
| `1` | Critical error, elevation denied/failed/timed out, invalid config, or `partial` with `--strict` |
| `2` | Unsupported platform (non-Windows) |
| `130` | Scan interrupted by the user (Ctrl+C) |

## Reports

Text reports contain the detected artifacts grouped by anti-cheat and subsystem,
plus scanner/host/config context. JSON reports add a versioned envelope:

```json
{
  "schema": 1,
  "scanner_version": "0.2.0",
  "generated_at": "2026-10-08T17:15:36+00:00",
  "host": {"hostname": "...", "windows_version": "...", "admin": true},
  "cli": {"workers": 5, "max_depth": 1},
  "config_sha256": "...",
  "total_detections": 31,
  "scan_status": "complete",
  "duration_seconds": 8.934,
  "checker_stats": {
    "ServiceChecker": {"failures": 0, "skipped": 0, "whitelisted": 0, "duration_s": 0.42}
  },
  "anti_cheats": {},
  "technical_info": []
}
```

A partial status means that at least one checker reported inaccessible data,
unavailable commands, timeouts, or other item-level failures. Treat partial
results as triage evidence rather than a complete forensic conclusion. Use
`--strict` when a partial scan must produce a non-zero exit code.

Reports can contain user paths, process names, registry values, hashes, and signer information. Store them accordingly.

## Configuration

`config/signatures.json` contains the maintained detection database
(documented in `config/signatures.md`). It is intentionally focused on
anti-cheat-specific components rather than general game or publisher
artifacts. Validate it with:

```powershell
python main.py --validate-config
```

`config/whitelist.json` can suppress selected files, processes, services,
folders, drivers, registry entries, tasks, or traces (all 8 keys must be
present; see `config/whitelist.example.json`). Whitelisted items are counted
in checker statistics but are not included as findings. Use `--no-whitelist`
for unfiltered audit runs.

## Limitations

- Heuristic matching can produce false positives or false negatives.
- Metadata and signer-subject matching do not prove that a binary is trusted.
  Kernel drivers are typically WHQL-signed by Microsoft; a Microsoft signer
  neither clears nor accuses — attribution uses `CompanyName`/`ProductName` first.
- Prefetch filenames are indicators only and are not fully parsed.
- BCD and firewall checks use targeted text inspection.
- The default filesystem search is shallow and does not cover every custom
  installation path; `--full` is unbounded in time — combine it with `--timeout`.
- Only the current user's hive (HKCU) is inspected; other users' hives
  require offline mounting and are out of scope.
- Event-log inspection covers the most recent System records only.
- Results should be correlated with independent forensic sources.

## Troubleshooting

- `partial` scan without admin rights: re-run elevated or accept triage-level
  results; `netstat -anob`, `bcdedit`, and BAM hives need privileges.
- PowerShell `Restricted` policy: the scanner runs its own probes with a
  process-scoped bypass; do not lower the machine policy.
- Slow `--full` scans: lower `--max-depth`, use `--include`, or set `--timeout`.
- Empty results on a non-Windows machine: the scanner refuses to run there
  (exit 2) — most probes are Win32-only.
- Config errors: run `python main.py --validate-config` before opening an issue.

## Security

Run the scanner from a trusted project directory. The application elevates a local Python process and should not be launched from an untrusted download or shared writable directory. Reports may contain sensitive system metadata.

PowerShell probes execute only scanner-generated scripts (paths quoted, no
user input interpolated). System tools are resolved to absolute paths under
`%Windows%\System32` with a restricted environment.

## License

Proprietary. See [LICENSE](LICENSE) for the complete terms.
