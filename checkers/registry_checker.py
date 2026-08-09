import logging
import re
from typing import List, Optional
import winreg

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex

from .base import BaseChecker
from .detection import CATEGORY_REG, Detection

logger = logging.getLogger(__name__)

TARGETS_PROC = "processes"
TARGETS_PROC_PROD = "processes+products"
TARGETS_PROC_SVC_PROD = "processes+services+products"


class RegistryChecker(BaseChecker):
    CATEGORY = CATEGORY_REG

    def __init__(
        self,
        ac_database: List[AntiCheatInfo],
        sig_index: Optional[SignatureIndex] = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self._all_targets_cache: dict[str, List[str]] = {}

    def _add(self, entry: str) -> None:
        self.append_detection(Detection(category=CATEGORY_REG, text=entry))

    def _get_targets(self, sources: str = TARGETS_PROC_PROD) -> List[str]:
        if sources not in (
            TARGETS_PROC,
            TARGETS_PROC_PROD,
            TARGETS_PROC_SVC_PROD,
        ):
            raise ValueError(f"Unknown target set: {sources!r}")
        if sources not in self._all_targets_cache:
            result = []
            for ac in self.ac_database:
                if sources == TARGETS_PROC_PROD:
                    items = ac.processes + ac.products
                elif sources == TARGETS_PROC_SVC_PROD:
                    items = ac.processes + ac.services + ac.products
                else:
                    items = ac.processes
                for item in items:
                    t = item.lower().replace(".exe", "").replace(".sys", "")
                    if len(t) >= 4:
                        result.append(t)
            self._all_targets_cache[sources] = result
        return self._all_targets_cache[sources]

    def _wow_subkey(self, subkey: str) -> Optional[str]:
        parts = subkey.split("\\", 1)
        if parts[0].upper() != "SOFTWARE":
            return None
        return f"SOFTWARE\\WOW6432Node\\{parts[1]}" if len(parts) > 1 else "SOFTWARE\\WOW6432Node"

    def _check_key_with_wow_variant(self, hive_str: str, subkey: str) -> None:
        self._check_key_exists(hive_str, subkey)
        if "WOW6432Node" in subkey or hive_str != "HKEY_LOCAL_MACHINE":
            return
        wow = self._wow_subkey(subkey)
        if wow:
            self._check_key_exists(hive_str, wow)

    def check(self) -> None:
        for ac in self.ac_database:
            for hive_str, subkey in ac.registry:
                self._check_key_with_wow_variant(hive_str, subkey)
        self._scan_uninstall_keys()
        self._scan_app_paths()
        self._scan_startup_keys()
        self._scan_muicache()
        self._scan_appcompat()

    def _check_key_exists(self, hive_str: str, subkey: str) -> None:
        try:
            hive = getattr(winreg, hive_str, None)
            if hive is None:
                logger.debug("_check_key_exists: unknown hive %r", hive_str)
                return
            try:
                handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                winreg.CloseKey(handle)
                entry = f"{hive_str}\\{subkey}"
                self._add(entry)
            except FileNotFoundError:
                pass  # Missing key: expected condition.
        except Exception as e:
            logger.debug("_check_key_exists %s\\%s failed: %s", hive_str, subkey, e)

    def _scan_uninstall_keys(self) -> None:
        hives = [("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE), ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER)]
        paths = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
        for hive_name, hive in hives:
            for path in paths:
                try:
                    root = winreg.OpenKey(hive, path)
                    for i in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            subkey_name = winreg.EnumKey(root, i)
                            full_path = f"{path}\\{subkey_name}"
                            subkey = winreg.OpenKey(root, subkey_name)
                            try:
                                display_name = str(winreg.QueryValueEx(subkey, "DisplayName")[0]).lower()
                                for ac in self.ac_database:
                                    targets = []
                                    for p in [ac.name] + ac.products:
                                        if len(p) >= 4:
                                            targets.append(re.escape(p.lower()))
                                    if not targets:
                                        continue
                                    pattern = re.compile(rf"\b({'|'.join(targets)})\b")
                                    if pattern.search(display_name):
                                        entry = f"REGISTRY UNINSTALL: {hive_name}\\{full_path} ({display_name})"
                                        self._add(entry)
                                        break
                            except FileNotFoundError:
                                pass  # Missing key: expected condition.
                            winreg.CloseKey(subkey)
                        except OSError as e:
                            logger.debug("_scan_uninstall_keys enum failed: %s", e)
                    winreg.CloseKey(root)
                except FileNotFoundError:
                    pass  # Missing key: expected condition.

    def _scan_app_paths(self) -> None:
        app_paths_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        hives = [("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE), ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER)]
        all_targets = []
        for ac in self.ac_database:
            for proc in ac.processes:
                if len(proc) >= 4:
                    all_targets.append(proc.lower())
        for hive_name, hive in hives:
            try:
                root = winreg.OpenKey(hive, app_paths_key)
                for i in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                        subkey_lower = subkey_name.lower()
                        for target_proc in all_targets:
                            if target_proc == subkey_lower:
                                entry = f"APP PATH: {hive_name}\\{app_paths_key}\\{subkey_name}"
                                self._add(entry)
                                break
                    except OSError as e:
                        logger.debug("_scan_app_paths enum failed: %s", e)
                winreg.CloseKey(root)
            except (FileNotFoundError, OSError) as e:
                logger.debug("_scan_app_paths open failed: %s", e)

    def _scan_startup_keys(self) -> None:
        startup_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        hives = [("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE), ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER)]
        all_targets = self._get_targets(TARGETS_PROC_SVC_PROD)
        for hive_name, hive in hives:
            for path in startup_paths:
                try:
                    handle = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(handle)[1]

                    pattern = None
                    if all_targets:
                        pattern = re.compile(rf"\b({'|'.join(re.escape(t) for t in all_targets)})\b")

                    for i in range(num_values):
                        try:
                            val_name, val_data, _ = winreg.EnumValue(handle, i)
                            combined = f"{val_name} {val_data}".lower()
                            if pattern and pattern.search(combined):
                                entry = f"STARTUP: {hive_name}\\{path}\\{val_name} = {val_data}"
                                self._add(entry)
                        except OSError as e:
                            logger.debug("_scan_startup_keys enum failed: %s", e)
                    winreg.CloseKey(handle)
                except (FileNotFoundError, OSError) as e:
                    logger.debug("_scan_startup_keys open failed: %s", e)

    def _scan_muicache(self) -> None:
        try:
            key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            num_values = winreg.QueryInfoKey(handle)[1]
            all_targets = self._get_targets(TARGETS_PROC_PROD)
            pattern = None
            if all_targets:
                pattern = re.compile(rf"\b({'|'.join(re.escape(t) for t in all_targets)})\b")
            for i in range(num_values):
                try:
                    val_name, _, _ = winreg.EnumValue(handle, i)
                    val_lower = val_name.lower()
                    if pattern and pattern.search(val_lower):
                        entry = f"MUICACHE EXECUTION: {val_name}"
                        self._add(entry)
                except OSError as e:
                    logger.debug("_scan_muicache enum failed: %s", e)
            winreg.CloseKey(handle)
        except (FileNotFoundError, OSError) as e:
            logger.debug("_scan_muicache failed: %s", e)

    def _scan_appcompat(self) -> None:
        try:
            key_path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            num_values = winreg.QueryInfoKey(handle)[1]
            all_targets = self._get_targets(TARGETS_PROC_PROD)
            pattern = None
            if all_targets:
                pattern = re.compile(rf"\b({'|'.join(re.escape(t) for t in all_targets)})\b")
            for i in range(num_values):
                try:
                    val_name, _, _ = winreg.EnumValue(handle, i)
                    val_lower = val_name.lower()
                    if pattern and pattern.search(val_lower):
                        entry = f"APPCOMPAT HISTORY: {val_name}"
                        self._add(entry)
                except OSError as e:
                    logger.debug("_scan_appcompat enum failed: %s", e)
            winreg.CloseKey(handle)
        except (FileNotFoundError, OSError) as e:
            logger.debug("_scan_appcompat failed: %s", e)
