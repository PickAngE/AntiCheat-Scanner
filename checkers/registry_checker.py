from __future__ import annotations

import logging
import re
import winreg
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_REG, Detection
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)

TARGETS_PROC = "processes"
TARGETS_PROC_PROD = "processes+products"
TARGETS_PROC_SVC_PROD = "processes+services+products"


class RegistryChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_REG

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self._all_targets_cache: dict[str, list[str]] = {}

    def _add(self, entry: str) -> None:
        self.append_detection(Detection(category=CATEGORY_REG, text=entry))

    def _get_targets(self, sources: str = TARGETS_PROC_PROD) -> list[str]:
        if sources not in {TARGETS_PROC, TARGETS_PROC_PROD, TARGETS_PROC_SVC_PROD}:
            raise ValueError(f"Unknown target set: {sources!r}")
        if sources not in self._all_targets_cache:
            result: list[str] = []
            for ac in self.ac_database:
                if sources == TARGETS_PROC_PROD:
                    items = ac.processes + ac.products
                elif sources == TARGETS_PROC_SVC_PROD:
                    items = ac.processes + ac.services + ac.products
                else:
                    items = ac.processes
                result.extend(
                    item.casefold().removesuffix(".exe").removesuffix(".sys")
                    for item in items
                    if len(item) >= 3
                )
            self._all_targets_cache[sources] = list(dict.fromkeys(result))
        return self._all_targets_cache[sources]

    def _wow_subkey(self, subkey: str) -> str | None:
        parts = subkey.split("\\", 1)
        if parts[0].casefold() != "software":
            return None
        return f"SOFTWARE\\WOW6432Node\\{parts[1]}" if len(parts) > 1 else "SOFTWARE\\WOW6432Node"

    def _check_key_with_wow_variant(self, hive_string: str, subkey: str) -> None:
        self._check_key_exists(hive_string, subkey)
        if "WOW6432Node" in subkey or hive_string != "HKEY_LOCAL_MACHINE":
            return
        wow_subkey = self._wow_subkey(subkey)
        if wow_subkey:
            self._check_key_exists(hive_string, wow_subkey)

    def check(self) -> None:
        for ac in self.ac_database:
            for hive, subkey in ac.registry:
                self._check_key_with_wow_variant(hive, subkey)
        self._scan_uninstall_keys()
        self._scan_app_paths()
        self._scan_startup_keys()
        self._scan_muicache()
        self._scan_appcompat()

    def _check_key_exists(self, hive_string: str, subkey: str) -> None:
        hive = getattr(winreg, hive_string, None)
        if hive is None:
            return
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ):
                self._add(f"{hive_string}\\{subkey}")
        except FileNotFoundError:
            return
        except OSError as exc:
            self.fail_count += 1
            logger.debug(
                "Registry key lookup failed for %s\\%s: %s", hive_string, subkey, format_error(exc)
            )

    def _scan_uninstall_keys(self) -> None:
        hives = (
            ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
            ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
        )
        paths = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        )
        for hive_name, hive in hives:
            for path in paths:
                try:
                    with winreg.OpenKey(hive, path) as root:
                        for index in range(winreg.QueryInfoKey(root)[0]):
                            try:
                                subkey_name = winreg.EnumKey(root, index)
                                with winreg.OpenKey(root, subkey_name) as subkey:
                                    display_name = str(
                                        winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    ).casefold()
                                    for ac in self.ac_database:
                                        targets = [
                                            re.escape(value.casefold())
                                            for value in [ac.name, *ac.products]
                                            if len(value) >= 4
                                        ]
                                        if targets and re.search(
                                            rf"\b({'|'.join(targets)})\b",
                                            display_name,
                                        ):
                                            self._add(
                                                f"REGISTRY UNINSTALL: {hive_name}\\{path}\\{subkey_name} ({display_name})"
                                            )
                                            break
                            except FileNotFoundError:
                                continue
                            except OSError as exc:
                                self.fail_count += 1
                                logger.debug("Uninstall key scan failed: %s", format_error(exc))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    self.fail_count += 1
                    logger.debug("Uninstall root scan failed: %s", format_error(exc))

    def _scan_app_paths(self) -> None:
        app_paths_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        hives = (
            ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
            ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
        )
        targets = {
            process.casefold()
            for ac in self.ac_database
            for process in ac.processes
            if len(process) >= 3
        }
        for hive_name, hive in hives:
            try:
                with winreg.OpenKey(hive, app_paths_key) as root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            subkey_name = winreg.EnumKey(root, index)
                            if subkey_name.casefold() in targets:
                                self._add(f"APP PATH: {hive_name}\\{app_paths_key}\\{subkey_name}")
                        except OSError as exc:
                            self.fail_count += 1
                            logger.debug("App Paths scan failed: %s", format_error(exc))
            except (FileNotFoundError, OSError) as exc:
                logger.debug("App Paths root scan failed: %s", format_error(exc))

    def _scan_startup_keys(self) -> None:
        startup_paths = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        )
        hives = (
            ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
            ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
        )
        targets = self._get_targets(TARGETS_PROC_SVC_PROD)
        pattern = (
            re.compile(rf"\b({'|'.join(re.escape(target) for target in targets)})\b")
            if targets
            else None
        )
        for hive_name, hive in hives:
            for path in startup_paths:
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as handle:
                        for index in range(winreg.QueryInfoKey(handle)[1]):
                            try:
                                value_name, value_data, _ = winreg.EnumValue(handle, index)
                                combined = f"{value_name} {value_data}".casefold()
                                if pattern and pattern.search(combined):
                                    self._add(
                                        f"STARTUP: {hive_name}\\{path}\\{value_name} = {value_data}"
                                    )
                            except OSError as exc:
                                self.fail_count += 1
                                logger.debug("Startup value scan failed: %s", format_error(exc))
                except (FileNotFoundError, OSError) as exc:
                    logger.debug("Startup key scan failed: %s", format_error(exc))

    def _scan_muicache(self) -> None:
        self._scan_user_values(
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            "MUICACHE EXECUTION",
            self._get_targets(TARGETS_PROC_PROD),
        )

    def _scan_appcompat(self) -> None:
        self._scan_user_values(
            r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
            "APPCOMPAT HISTORY",
            self._get_targets(TARGETS_PROC_PROD),
        )

    def _scan_user_values(self, path: str, label: str, targets: list[str]) -> None:
        pattern = (
            re.compile(rf"\b({'|'.join(re.escape(target) for target in targets)})\b")
            if targets
            else None
        )
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as handle:
                for index in range(winreg.QueryInfoKey(handle)[1]):
                    try:
                        value_name, _, _ = winreg.EnumValue(handle, index)
                        if pattern and pattern.search(value_name.casefold()):
                            self._add(f"{label}: {value_name}")
                    except OSError as exc:
                        self.fail_count += 1
                        logger.debug("%s value scan failed: %s", label, format_error(exc))
        except (FileNotFoundError, OSError) as exc:
            logger.debug("%s key scan failed: %s", label, format_error(exc))
