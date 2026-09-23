from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_DRV, Detection
from checkers.matchers import metadata_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.helpers import batch_get_digital_signatures, get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)


class DriverFileChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_DRV

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self.target_drivers = {
            driver.casefold(): ac.name for ac in ac_database for driver in ac.drivers
        }

    def check(self) -> None:
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        drivers_path = Path(system_root) / "System32" / "drivers"
        if not drivers_path.exists():
            return
        matched_paths: set[str] = set()
        for file_path in drivers_path.glob("*.sys"):
            try:
                file_name = file_path.name.casefold()
                if file_name in self.target_drivers:
                    self._append_driver(file_path, self.target_drivers[file_name])
                    matched_paths.add(str(file_path))
                    continue
                properties = get_file_properties(str(file_path))
                for ac in self.ac_database:
                    if metadata_matches(properties, ac.companies, ac.products):
                        self._append_driver(
                            file_path,
                            ac.name,
                            description=f"DRIVER METADATA: {file_path} ({properties.get('CompanyName')})",
                        )
                        matched_paths.add(str(file_path))
                        break
            except OSError as exc:
                self.fail_count += 1
                logger.error(
                    "DriverFileChecker could not inspect %s: %s", file_path, format_error(exc)
                )
        self._check_certificates(drivers_path, matched_paths)

    def _append_driver(
        self,
        path: Path,
        ac_name: str | None,
        description: str | None = None,
    ) -> None:
        self.append_detection(
            Detection(
                category=CATEGORY_DRV,
                text=description or str(path),
                ac_name=ac_name,
                active=False,
                raw=str(path),
            )
        )

    def _check_certificates(self, drivers_path: Path, already_matched: set[str]) -> None:
        try:
            company_owners = [
                (company.casefold(), ac.name)
                for ac in self.ac_database
                for company in ac.companies
                if len(company) >= 4
            ]
            paths = [
                str(path) for path in drivers_path.glob("*.sys") if str(path) not in already_matched
            ]
            if not paths:
                return
            signatures = batch_get_digital_signatures(paths)
            for path, subject in signatures.items():
                subject_lower = subject.casefold()
                owner = next(
                    (
                        ac_name
                        for company, ac_name in company_owners
                        if re.search(rf"\b{re.escape(company)}\b", subject_lower)
                    ),
                    None,
                )
                if owner:
                    self._append_driver(
                        Path(path),
                        owner,
                        description=f"DRIVER CERT: {path} (Signed: {subject})",
                    )
        except OSError as exc:
            self.fail_count += 1
            logger.error("Driver certificate scan failed: %s", format_error(exc))
