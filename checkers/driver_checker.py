import logging
import os
import re
from pathlib import Path
from typing import FrozenSet, List

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

        for file_path in drivers_path.glob("*.sys"):
            try:
                fname = file_path.name.lower()
                if fname in target_drivers_set:
                    self.append_detection(Detection(
                        category=CATEGORY_DRV,
                        text=str(file_path),
                        active=True,
                        raw=str(file_path),
                    ))
                    continue
                props = get_file_properties(str(file_path))
                for ac in self.ac_database:
                    if metadata_matches(props, ac.companies, ac.products):
                        self.append_detection(Detection(
                            category=CATEGORY_DRV,
                            text=f"DRIVER METADATA: {file_path} ({props.get('CompanyName')})",
                            active=True,
                            raw=str(file_path),
                        ))
                        break
            except Exception as e:
                self.fail_count += 1
                logger.error(
                    "DriverFileChecker: unexpected error on %s: %s",
                    file_path, e, exc_info=True,
                )
                continue

        self._check_certificates(drivers_path, target_drivers_set)

    def _check_certificates(self, drivers_path: Path, already_matched: FrozenSet[str]) -> None:
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
            for path, subject in signatures.items():
                if Path(path).name.lower() in already_matched:
                    continue
                subject_lower = subject.lower()
                for company in all_companies:
                    c = company.lower()
                    if len(c) < 4:
                        continue
                    if re.search(rf"\b{re.escape(c)}\b", subject_lower):
                        entry = f"DRIVER CERT: {path} (Signed: {subject})"
                        self.append_detection(Detection(
                            category=CATEGORY_DRV,
                            text=entry,
                            active=True,
                            raw=path,
                        ))
                        break
        except Exception as e:
            logger.error("%s failed", type(self).__name__, exc_info=True)
