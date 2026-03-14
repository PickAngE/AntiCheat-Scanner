import os
from pathlib import Path
from typing import List, Set
from utils.helpers import get_drives, get_file_properties
from .matchers import folder_name_matches_target, target_matches, metadata_matches
from config.signatures import AntiCheatInfo
COMMON_ROOTS = [
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "Games",
    "XboxGames",
    "Riot Games",
    "Epic Games",
    "Ubisoft",
    "SteamLibrary",
    "Steam",
    "Users",
    "Downloads",
    "Desktop",
    "Documents",
    "Temp",
    "AppData\\Local\\Temp",
    "Windows\\Temp",
    "Windows\\Prefetch",
]
class FileChecker:
    def __init__(self, ac_database: List[AntiCheatInfo]) -> None:
        self.ac_database = ac_database
        self.target_names = []
        for ac in ac_database:
            self.target_names.extend(ac.folders)
        self.found: List[str] = []
    def check(self) -> None:
        paths_to_check: Set[str] = set()
        self._collect_from_env_vars(paths_to_check)
        for drive in get_drives():
            self._collect_from_drive(Path(drive), paths_to_check)
        for path_str in sorted(paths_to_check):
            try:
                path = Path(path_str)
                if path.exists():
                    self.found.append(str(path))
            except OSError:
                continue
    def _collect_from_env_vars(self, paths: Set[str]) -> None:
        env_vars = ["APPDATA", "LOCALAPPDATA", "USERPROFILE", "PROGRAMFILES", "PROGRAMFILES(X86)"]
        for ev in env_vars:
            val = os.environ.get(ev)
            if not val: continue
            base = Path(val)
            for target_name in self.target_names:
                paths.add(str(base / target_name))
    def _collect_from_drive(self, drive_path: Path, paths: Set[str]) -> None:
        for root_name in COMMON_ROOTS:
            potential_root = drive_path / root_name
            if not potential_root.exists() and root_name in ["Downloads", "Desktop", "Documents", "Temp"]:
                user_profile = os.environ.get("USERPROFILE")
                if user_profile: potential_root = Path(user_profile) / root_name
            if not potential_root.exists(): continue
            for target_name in self.target_names:
                paths.add(str(potential_root / target_name))
            self._scan_and_validate(potential_root, paths)
    def _scan_and_validate(self, root: Path, paths: Set[str]) -> None:
        try:
            for item in root.iterdir():
                if target_matches(item.name, self.target_names):
                    paths.add(str(item))
                if item.is_file() and item.suffix.lower() in [".exe", ".sys"]:
                    props = get_file_properties(str(item))
                    for ac in self.ac_database:
                        if metadata_matches(props, ac.companies, ac.products):
                            self.found.append(f"METADATA MATCH: {item} ({props.get('CompanyName')})")
                            break
                if item.is_dir():
                    try:
                        for sub in item.iterdir():
                            if target_matches(sub.name, self.target_names):
                                paths.add(str(sub))
                            if sub.is_file() and sub.suffix.lower() in [".exe", ".sys"]:
                                props = get_file_properties(str(sub))
                                for ac in self.ac_database:
                                    if metadata_matches(props, ac.companies, ac.products):
                                        self.found.append(f"METADATA MATCH: {sub} ({props.get('CompanyName')})")
                                        break
                    except OSError: pass
        except OSError: pass
