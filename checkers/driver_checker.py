from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import ClassVar

import psutil

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_DRV, Detection
from checkers.matchers import extract_exe_path, metadata_matches, normalize_alnum
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.helpers import batch_get_digital_signatures, get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)



DRIVER_PREFIXES = ("DRIVER METADATA:", "DRIVER CERT:")


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
        driver_files: list[Path] = []
        if drivers_path.exists():
            try:
                driver_files = sorted(drivers_path.glob("*.sys"))
            except OSError as exc:
                self.fail_count += 1
                logger.error(
                    "DriverFileChecker could not list %s: %s", drivers_path, format_error(exc)
                )
                return
        matched_paths: set[str] = set()


        for file_path in driver_files:
            self._inspect_driver_file(file_path, matched_paths)




        seen = {os.path.normcase(os.path.normpath(p)) for p in matched_paths}
        extra_files: list[Path] = []
        for service_path in self._service_driver_paths():
            normalized = os.path.normcase(os.path.normpath(service_path))
            if normalized in seen:
                continue
            seen.add(normalized)
            extra_files.append(Path(service_path))
            self._inspect_driver_file(Path(service_path), matched_paths)
        self._check_certificates([*driver_files, *extra_files], matched_paths)

    def _inspect_driver_file(self, file_path: Path, matched_paths: set[str]) -> None:
        file_name = file_path.name.casefold()
        if file_name in self.target_drivers:
            self._append_driver(file_path, self.target_drivers[file_name])
            matched_paths.add(str(file_path))
            return
        properties = get_file_properties(str(file_path))
        for ac in self.ac_database:
            if metadata_matches(properties, ac.companies, ac.products):
                self._append_driver(
                    file_path,
                    ac.name,
                    description=f"{DRIVER_PREFIXES[0]} {file_path} "
                    f"({properties.get('CompanyName')})",
                )
                matched_paths.add(str(file_path))
                break

    def _service_driver_paths(self) -> list[str]:
        paths: list[str] = []
        try:
            services = psutil.win_service_iter()
        except (OSError, psutil.Error) as exc:
            logger.debug("Driver service-image scan unavailable: %s", format_error(exc))
            return paths
        for service in services:
            try:
                try:
                    raw_binpath = service.binpath() or ""
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                exe_path = extract_exe_path(raw_binpath)
                if not exe_path or not exe_path.casefold().endswith(".sys"):
                    continue
                if os.path.exists(exe_path) and exe_path not in paths:
                    paths.append(exe_path)
            except (OSError, psutil.Error, TypeError, ValueError) as exc:
                logger.debug("Driver service-image lookup failed: %s", format_error(exc))
        return paths

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

    def _check_certificates(self, driver_files: list[Path], already_matched: set[str]) -> None:
        try:
            company_owners = [
                (normalize_alnum(company), ac.name)
                for ac in self.ac_database
                for company in ac.companies
                if len(normalize_alnum(company)) >= 4
            ]
            paths = [str(path) for path in driver_files if str(path) not in already_matched]
            if not paths:
                return
            signatures = batch_get_digital_signatures(paths)
            for path, subject in signatures.items():
                subject_normalized = normalize_alnum(subject)
                owner = next(
                    (
                        ac_name
                        for company, ac_name in company_owners
                        if company and company in subject_normalized
                    ),
                    None,
                )
                if owner:
                    self._append_driver(
                        Path(path),
                        owner,
                        description=f"{DRIVER_PREFIXES[1]} {path} (Signed: {subject})",
                    )
        except OSError as exc:
            self.fail_count += 1
            logger.error("Driver certificate scan failed: %s", format_error(exc))
