<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
import logging
import os
import subprocess
from pathlib import Path
from typing import List

from .base import BaseChecker
from .matchers import metadata_matches
from utils.helpers import get_file_properties, ps_escape_path

logger = logging.getLogger(__name__)


class DriverFileChecker(BaseChecker):
<<<<<<< HEAD
=======
=======
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
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        drivers_path = Path(system_root) / "System32" / "drivers"
        if not drivers_path.exists():
            return
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)

        target_drivers: List[str] = []
        for ac in self.ac_database:
            target_drivers.extend(ac.drivers)
        target_drivers_set = frozenset(d.lower() for d in target_drivers)

        try:
            for file_path in drivers_path.glob("*.sys"):
                fname = file_path.name.lower()
                if fname in target_drivers_set:
<<<<<<< HEAD
=======
=======
        target_drivers: List[str] = []
        for ac in self.ac_database:
            target_drivers.extend(ac.drivers)
        target_drivers_lower = [d.lower() for d in target_drivers]
        try:
            for file_path in drivers_path.glob("*.sys"):
                fname = file_path.name.lower()
                if fname in target_drivers_lower:
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                    self.found.append(str(file_path))
                    continue
                props = get_file_properties(str(file_path))
                for ac in self.ac_database:
                    if metadata_matches(props, ac.companies, ac.products):
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                        self.found.append(
                            f"DRIVER METADATA: {file_path} ({props.get('CompanyName')})"
                        )
                        break
        except Exception as e:
            logger.debug("DriverFileChecker scan failed: %s", e)

        self._check_certificates(drivers_path, target_drivers_set)

    def _check_certificates(self, drivers_path: Path, already_matched: set) -> None:
<<<<<<< HEAD
=======
=======
                        self.found.append(f"DRIVER METADATA: {file_path} ({props.get('CompanyName')})")
                        break
        except Exception:
            pass
        self._check_certificates(drivers_path, target_drivers_lower)
    def _check_certificates(self, drivers_path: Path, already_matched: List[str]) -> None:
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
        try:
            all_companies: List[str] = []
            for ac in self.ac_database:
                all_companies.extend(ac.companies)
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)

            safe_path = ps_escape_path(str(drivers_path))
            ps_cmd = (
                f"Get-ChildItem -LiteralPath '{safe_path}' -Filter '*.sys' "
                "-ErrorAction SilentlyContinue | "
                "ForEach-Object { "
                "  $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName "
                "-ErrorAction SilentlyContinue; "
<<<<<<< HEAD
=======
=======
            ps_cmd = (
                f"Get-ChildItem '{drivers_path}\\*.sys' -ErrorAction SilentlyContinue | "
                "ForEach-Object { "
                "  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue; "
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                "  if ($sig.SignerCertificate) { "
                "    $_.FullName + '|' + $sig.SignerCertificate.Subject "
                "  } "
                "}"
            )
            output = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                text=True,
                errors="ignore",
                timeout=120,
            )
            found_set = set(self.found)
<<<<<<< HEAD
=======
=======
                text=True, errors="ignore", timeout=120,
            )
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
            for line in output.splitlines():
                parts = line.split("|", 1)
                if len(parts) != 2:
                    continue
                path, subject = parts[0].strip(), parts[1].strip()
                if Path(path).name.lower() in already_matched:
                    continue
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
                if any(f"DRIVER METADATA:" in f and path in f for f in self.found):
                    continue
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                subject_lower = subject.lower()
                for company in all_companies:
                    if company.lower() in subject_lower:
                        entry = f"DRIVER CERT: {path} (Signed: {subject})"
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                        if entry not in found_set:
                            found_set.add(entry)
                            self.found.append(entry)
                        break
        except Exception as e:
            logger.debug("_check_certificates failed: %s", e)
<<<<<<< HEAD
=======
=======
                        if entry not in self.found:
                            self.found.append(entry)
                        break
        except Exception:
            pass
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
