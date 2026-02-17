import os
from pathlib import Path
from typing import List, Set

from utils.helpers import get_drives
from .matchers import folder_name_matches_target


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
]


class FileChecker:
    def __init__(self, target_folders_names: List[str]) -> None:
        self.target_folders_names = target_folders_names
        self.found: List[str] = []

    def check(self) -> None:
        folders_to_check: Set[str] = set()
        self._collect_from_appdata(folders_to_check)
        for drive in get_drives():
            self._collect_from_drive(Path(drive), folders_to_check)
        for path_str in sorted(folders_to_check):
            try:
                path = Path(path_str)
                if path.exists():
                    self.found.append(str(path))
            except OSError:
                continue

    def _collect_from_appdata(self, folders: Set[str]) -> None:
        for env_var in ["%AppData%", "%LocalAppData%"]:
            try:
                base = Path(os.path.expandvars(env_var))
                for target_name in self.target_folders_names:
                    folders.add(str(base / target_name))
            except Exception:
                pass

    def _collect_from_drive(self, drive_path: Path, folders: Set[str]) -> None:
        for target_name in self.target_folders_names:
            segments = target_name.replace("/", "\\").split("\\")
            head = segments[0].strip()
            if head and folder_name_matches_target(head, self.target_folders_names):
                folders.add(str(drive_path / head))
            folders.add(str(drive_path / target_name))
        for root_name in COMMON_ROOTS:
            potential_root = drive_path / root_name
            if not potential_root.exists():
                continue
            for target_name in self.target_folders_names:
                folders.add(str(potential_root / target_name))
            self._collect_exact_under_root(potential_root, folders)
            if "Steam" in root_name:
                self._collect_steam_common(potential_root, folders)

    def _collect_exact_under_root(self, root: Path, folders: Set[str]) -> None:
        try:
            for item in root.iterdir():
                if not item.is_dir():
                    continue
                if not folder_name_matches_target(item.name, self.target_folders_names):
                    continue
                folders.add(str(item))
                try:
                    for sub in item.iterdir():
                        if sub.is_dir() and folder_name_matches_target(sub.name, self.target_folders_names):
                            folders.add(str(sub))
                except OSError:
                    pass
        except OSError:
            pass

    def _collect_steam_common(self, steam_root: Path, folders: Set[str]) -> None:
        steam_common = steam_root / "steamapps" / "common"
        if not steam_common.exists():
            return
        try:
            for game_dir in steam_common.iterdir():
                if not game_dir.is_dir():
                    continue
                try:
                    for sub in game_dir.iterdir():
                        if sub.is_dir() and folder_name_matches_target(sub.name, self.target_folders_names):
                            folders.add(str(sub))
                except OSError:
                    pass
        except OSError:
            pass
