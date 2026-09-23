# Anti-Cheat Scanner

Anti-Cheat Scanner is a Windows utility for identifying anti-cheat software, related files, services, drivers, registry entries, and execution traces on a local machine.

## Supported targets

- ACE / AntiCheatExpert
- EA Javelin / EA Anti-Cheat
- Easy Anti-Cheat
- BattlEye
- HoYoProtect

## Detection areas

### Runtime

- Running processes
- Windows services
- Loaded filter drivers
- DriverQuery entries
- Network connections and named pipes

### Files and binaries

- Known anti-cheat folders
- File metadata
- SHA-256 hashes
- Authenticode signer subjects
- Scheduled tasks
- Prefetch filename indicators

### Windows artifacts

- Installed services and registry keys
- Uninstall entries
- Application Paths
- Startup entries
- MuiCache
- AppCompat history
- BAM execution records
- Defender exclusions
- Firewall rules
- DNS cache
- Event log indicators
- Boot configuration text

## Architecture

The scanner uses a common `BaseChecker` interface and a normalized `Detection` object. Checkers are created by `checkers.registry` and can run concurrently. Signature data is loaded from `config/signatures.json` and indexed for exact-name lookups.

The scanner distinguishes evidence from runtime state. A driver file found on disk is reported as present evidence, while loaded-driver evidence is collected separately by runtime checks. Runtime process detection relies on exact executable or service names; fuzzy name similarity is not used as standalone evidence.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- Administrator privileges for complete coverage
- `pywin32` and `psutil`

## Installation

```powershell
git clone https://github.com/PickAngE/Anti-Cheat-Scanner.git
cd Anti-Cheat-Scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For development tools:

```powershell
python -m pip install -r requirements-dev.txt
```

## Usage

A direct interactive launch waits before closing. Use `--no-pause` for automation. The Windows PowerShell launcher uses the local virtual environment and keeps the console available for diagnostics:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_scanner.ps1
```

You can also run the CLI directly from an activated environment:

```powershell
python main.py
```

The default report is written to the project directory. Use `--output-dir` to select another directory.

```powershell
python main.py --output-dir C:\Reports --json
```

Available options:

```text
--json              Write a JSON report
--workers N         Number of concurrent checkers
--max-depth N       Maximum filesystem search depth
--full              Scan configured roots recursively
--output-dir PATH   Report destination
--pause             Wait for Enter before exiting
--no-pause          Exit without waiting for Enter
--strict            Return non-zero for a partial scan
```

The scanner requests elevation through UAC when needed. A denied elevation or a failed elevated scan returns a non-zero exit code.

## Reports

Text reports contain the detected artifacts grouped by anti-cheat and subsystem. JSON reports contain the same findings with checker statistics, scan duration, and a `complete` or `partial` scan status.

A partial status means that at least one checker reported inaccessible data, unavailable commands, or other item-level failures. Treat partial results as triage evidence rather than a complete forensic conclusion. Use `--strict` when a partial scan must produce a non-zero exit code.

Reports can contain user paths, process names, registry values, hashes, and signer information. Store them accordingly.

## Configuration

`config/signatures.json` contains the maintained detection database. The database is intentionally focused on anti-cheat-specific components rather than general game or publisher artifacts.

`config/whitelist.json` can suppress selected files, processes, services, or folders. Whitelisted items are counted in checker statistics but are not included as findings.

## Limitations

- Heuristic matching can produce false positives or false negatives.
- Metadata and signer-subject matching do not prove that a binary is trusted.
- Prefetch filenames are indicators only and are not fully parsed.
- BCD and firewall checks use targeted text inspection.
- The default filesystem search is shallow and does not cover every custom installation path.
- Results should be correlated with independent forensic sources.

## Project conventions

All project-authored source, logs, documentation, configuration, and launcher text are in English. Operating-system messages may use the language configured in Windows. Python source files and tests contain no comments or docstrings.

## Development checks

```powershell
python -m pytest -q
python -m ruff check .
python -m mypy .
```

## Security

Run the scanner from a trusted project directory. The application elevates a local Python process and should not be launched from an untrusted download or shared writable directory. Reports may contain sensitive system metadata.

## License

Proprietary. See [LICENSE](LICENSE) for the complete terms.
