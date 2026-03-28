import re
from typing import List, Tuple
import winreg
from config.signatures import AntiCheatInfo
class RegistryChecker:
    def __init__(self, ac_database: List[AntiCheatInfo]) -> None:
        self.ac_database = ac_database
        self.found: List[str] = []
    def check(self) -> None:
        for ac in self.ac_database:
            for hive_str, subkey in ac.registry:
                self._check_key_exists(hive_str, subkey)
                if "WOW6432Node" not in subkey and (hive_str == "HKEY_LOCAL_MACHINE" or hive_str == "HKEY_CURRENT_USER"):
                    parts = subkey.split("\\", 1)
                    wow_subkey = f"{parts[0]}\\WOW6432Node\\{parts[1]}" if len(parts) > 1 else f"SOFTWARE\\WOW6432Node\\{subkey}"
                    self._check_key_exists(hive_str, wow_subkey)
        self._scan_uninstall_keys()
        self._scan_app_paths()
        self._scan_startup_keys()
        self._scan_muicache()
        self._scan_appcompat()
    def _check_key_exists(self, hive_str: str, subkey: str) -> None:
        try:
            hive = getattr(winreg, hive_str, None)
            if hive is None: return
            try:
                handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                winreg.CloseKey(handle)
                entry = f"{hive_str}\\{subkey}"
                if entry not in self.found:
                    self.found.append(entry)
            except FileNotFoundError: pass
        except Exception: pass
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
                                        if entry not in self.found:
                                            self.found.append(entry)
                                        break
                            except FileNotFoundError: pass
                            winreg.CloseKey(subkey)
                        except OSError: pass
                    winreg.CloseKey(root)
                except FileNotFoundError: pass
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
                                if entry not in self.found:
                                    self.found.append(entry)
                                break
                    except OSError: pass
                winreg.CloseKey(root)
            except (FileNotFoundError, OSError): pass
    def _scan_startup_keys(self) -> None:
        startup_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        hives = [("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE), ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER)]
        all_targets = []
        for ac in self.ac_database:
            for item in ac.processes + ac.services + ac.products:
                t = item.lower().replace(".exe", "").replace(".sys", "")
                if len(t) >= 4:
                    all_targets.append(t)
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
                                if entry not in self.found:
                                    self.found.append(entry)
                        except OSError:
                            continue
                    winreg.CloseKey(handle)
                except (FileNotFoundError, OSError):
                    continue
    def _scan_muicache(self) -> None:
        try:
            key_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            num_values = winreg.QueryInfoKey(handle)[1]
            all_targets = []
            for ac in self.ac_database:
                for item in ac.processes + ac.products:
                    t = item.lower().replace(".exe", "").replace(".sys", "")
                    if len(t) >= 4:
                        all_targets.append(t)
            pattern = None
            if all_targets:
                pattern = re.compile(rf"\b({'|'.join(re.escape(t) for t in all_targets)})\b")
                
            for i in range(num_values):
                try:
                    val_name, _, _ = winreg.EnumValue(handle, i)
                    val_lower = val_name.lower()
                    if pattern and pattern.search(val_lower):
                        entry = f"MUICACHE EXECUTION: {val_name}"
                        if entry not in self.found:
                            self.found.append(entry)
                except OSError: pass
            winreg.CloseKey(handle)
        except (FileNotFoundError, OSError): pass
    def _scan_appcompat(self) -> None:
        try:
            key_path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            num_values = winreg.QueryInfoKey(handle)[1]
            all_targets = []
            for ac in self.ac_database:
                for item in ac.processes + ac.products:
                    t = item.lower().replace(".exe", "").replace(".sys", "")
                    if len(t) >= 4:
                        all_targets.append(t)
            pattern = None
            if all_targets:
                pattern = re.compile(rf"\b({'|'.join(re.escape(t) for t in all_targets)})\b")
                
            for i in range(num_values):
                try:
                    val_name, _, _ = winreg.EnumValue(handle, i)
                    val_lower = val_name.lower()
                    if pattern and pattern.search(val_lower):
                        entry = f"APPCOMPAT HISTORY: {val_name}"
                        if entry not in self.found:
                            self.found.append(entry)
                except OSError: pass
            winreg.CloseKey(handle)
        except (FileNotFoundError, OSError): pass
