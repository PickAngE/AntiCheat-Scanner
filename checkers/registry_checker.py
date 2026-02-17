from typing import List, Tuple

import winreg


class RegistryChecker:
    def __init__(self, target_keys: List[Tuple[str, str]]) -> None:
        self.target_keys = target_keys
        self.found: List[str] = []

    def check(self) -> None:
        for hive_str, subkey in self.target_keys:
            try:
                hive = getattr(winreg, hive_str, None)
                if hive is None:
                    continue
                with winreg.OpenKey(hive, subkey):
                    self.found.append(f"{hive_str}\\{subkey}")
            except (FileNotFoundError, OSError, PermissionError):
                continue
