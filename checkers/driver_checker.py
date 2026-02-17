import os
from pathlib import Path
from typing import List

from .matchers import target_matches


class DriverFileChecker:
    def __init__(self, target_drivers: List[str]) -> None:
        self.target_drivers = target_drivers
        self.found: List[str] = []

    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        drivers_path = Path(system_root) / "System32" / "drivers"
        if not drivers_path.exists():
            return
        try:
            for file_path in drivers_path.glob("*.sys"):
                fname = file_path.name.lower()
                if target_matches(fname, self.target_drivers):
                    self.found.append(str(file_path))
        except Exception:
            pass
