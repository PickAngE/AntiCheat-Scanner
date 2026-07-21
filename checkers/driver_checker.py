import logging
import os
from pathlib import Path
from typing import List

from .base import BaseChecker
from .detection import CATEGORY_DRV, Detection
from .matchers import metadata_matches
from utils.helpers import batch_get_digital_signatures, get_file_properties

logger = logging.getLogger(__name__)


class DriverFileChecker(BaseChecker):
    CATEGORY = CATEGORY_DRV

    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        drivers_path = Path(system_root) / "System32" / "drivers"
        if not drivers_path.exists():
            return

        target_drivers: List[str] = []
        for ac in self.ac_database:
            target_drivers.extend(ac.drivers)
        target_drivers_set = frozenset(d.lower() for d in target_drivers)

        try:
            for file_path in drivers_path.glob("*.sys"):
                fname = file_path.name.lower()
                if fname in target_drivers_set:
                    self.found.append(Detection(
                        category=CATEGORY_DRV,
                        text=str(file_path),
                        active=True,
                        raw=str(file_path),
                    ))
                    continue
                props = get_file_properties(str(file_path))
                for ac in self.ac_database:
                    if metadata_matches(props, ac.companies, ac.products):
                        self.found.append(Detection(
                            category=CATEGORY_DRV,
                            text=f"DRIVER METADATA: {file_path} ({props.get('CompanyName')})",
                            active=True,
                            raw=str(file_path),
                        ))
                        break
        except Exception as e:
            logger.debug("DriverFileChecker scan failed: %s", e)

        self._check_certificates(drivers_path, target_drivers_set)

    def _check_certificates(self, drivers_path: Path, already_matched: frozenset) -> None:
        try:
            all_companies: List[str] = []
            for ac in self.ac_database:
                all_companies.extend(ac.companies)

            sys_paths = [
                str(path)
                for path in drivers_path.glob("*.sys")
                if path.name.lower() not in already_matched
            ]
            if not sys_paths:
                return

            signatures = batch_get_digital_signatures(sys_paths)
            found_texts = {d.text for d in self.found}
            for path, subject in signatures.items():
                if Path(path).name.lower() in already_matched:
                    continue
                subject_lower = subject.lower()
                for company in all_companies:
                    if company.lower() in subject_lower:
                        entry = f"DRIVER CERT: {path} (Signed: {subject})"
                        if entry not in found_texts:
                            found_texts.add(entry)
                            self.found.append(Detection(
                                category=CATEGORY_DRV,
                                text=entry,
                                active=True,
                                raw=path,
                            ))
                        break
        except Exception as e:
            logger.debug("_check_certificates failed: %s", e)
