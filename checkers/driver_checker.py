from typing import List
import os
import subprocess
from pathlib import Path
from .matchers import metadata_matches
from utils.helpers import get_file_properties
from config.signatures import AntiCheatInfo
class DriverFileChecker:
    def __init__(self, ac_database: List[AntiCheatInfo]) -> None:
        self.ac_database = ac_database
        self.found: List[str] = []
    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        drivers_path = Path(system_root) / "System32" / "drivers"
        if not drivers_path.exists():
            return
        target_drivers: List[str] = []
        for ac in self.ac_database:
            target_drivers.extend(ac.drivers)
        target_drivers_lower = [d.lower() for d in target_drivers]
        try:
            for file_path in drivers_path.glob("*.sys"):
                fname = file_path.name.lower()
                if fname in target_drivers_lower:
                    self.found.append(str(file_path))
                    continue
                props = get_file_properties(str(file_path))
                for ac in self.ac_database:
                    if metadata_matches(props, ac.companies, ac.products):
                        self.found.append(f"DRIVER METADATA: {file_path} ({props.get('CompanyName')})")
                        break
        except Exception:
            pass
        self._check_certificates(drivers_path, target_drivers_lower)
    def _check_certificates(self, drivers_path: Path, already_matched: List[str]) -> None:
        try:
            all_companies: List[str] = []
            for ac in self.ac_database:
                all_companies.extend(ac.companies)
            ps_cmd = (
                f"Get-ChildItem '{drivers_path}\\*.sys' -ErrorAction SilentlyContinue | "
                "ForEach-Object { "
                "  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; "
                "  if ($sig.SignerCertificate) { "
                "    $_.FullName + '|' + $sig.SignerCertificate.Subject "
                "  } "
                "}"
            )
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                text=True, errors="ignore", timeout=120,
            )
            for line in output.splitlines():
                parts = line.split("|", 1)
                if len(parts) != 2:
                    continue
                path, subject = parts[0].strip(), parts[1].strip()
                if Path(path).name.lower() in already_matched:
                    continue
                if any(f"DRIVER METADATA:" in f and path in f for f in self.found):
                    continue
                subject_lower = subject.lower()
                for company in all_companies:
                    if company.lower() in subject_lower:
                        entry = f"DRIVER CERT: {path} (Signed: {subject})"
                        if entry not in self.found:
                            self.found.append(entry)
                        break
        except Exception:
            pass
