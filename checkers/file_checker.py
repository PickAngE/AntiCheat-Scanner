from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_FOLDER, Detection
from checkers.matchers import folder_name_matches_target, metadata_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.helpers import get_drives, get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)

COMMON_ROOTS = (
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
    r"AppData\Local\Temp",
    r"Windows\Temp",
    r"Windows\Prefetch",
)

_USER_RELATIVE_ROOTS = frozenset(
    {"Downloads", "Desktop", "Documents", "Temp", r"AppData\Local\Temp"}
)
_SKIP_DIRS = frozenset(
    {
        "System Volume Information",
        "$Recycle.Bin",
        "WinSxS",
        "Installer",
        "servicing",
        "node_modules",
        "INetCache",
        "Temp",
        "OneDrive",
        "NTUSER.DAT",
    }
)
_METADATA_SCAN_ROOTS = frozenset(
    {"Downloads", "Desktop", "Documents", "Temp", r"AppData\Local\Temp"}
)


class FileChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_FOLDER

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
        max_depth: int | None = 1,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self.max_depth = None if max_depth is None else max(0, max_depth)
        self.target_names = [folder for ac in ac_database for folder in ac.folders]

    def check(self) -> None:
        paths: set[str] = set()
        self._collect_from_environment(paths)
        user_profile = os.environ.get("USERPROFILE")
        visited: set[str] = set()
        for drive in get_drives():
            self._collect_from_drive(Path(drive), paths, user_profile, visited)
        for path_string in sorted(paths):
            try:
                path = Path(path_string)
                if path.exists():
                    self.append_detection(Detection(category=CATEGORY_FOLDER, text=str(path)))
            except OSError as exc:
                self.skipped_count += 1
                logger.warning(
                    "FileChecker could not inspect %s: %s", path_string, format_error(exc)
                )
        if self.skipped_count:
            logger.info("FileChecker skipped %d inaccessible paths", self.skipped_count)

    def _join_target(self, base: Path, target: str, root_name: str | None = None) -> Path:
        target_path = Path(target.replace("/", "\\"))
        if target_path.is_absolute():
            return target_path
        target_text = target.replace("/", "\\").rstrip("\\")
        base_text = str(base).replace("/", "\\").rstrip("\\")
        prefixes = [
            root_name,
            base_text.rsplit("\\", 1)[-1],
            "AppData",
            "AppData\\Local",
            "AppData\\Roaming",
            "Windows",
        ]
        for prefix in prefixes:
            if not prefix:
                continue
            prefix_text = prefix.replace("/", "\\").rstrip("\\")
            if target_text.casefold().startswith(prefix_text.casefold() + "\\"):
                relative = target_text[len(prefix_text) + 1 :]
                if base_text.casefold().endswith(
                    "\\" + prefix_text.casefold()
                ) or prefix_text.casefold() in {
                    "appdata\\local\\temp",
                    "windows\\temp",
                }:
                    return base / relative
        return base / target_path

    def _collect_from_environment(self, paths: set[str]) -> None:
        for variable in (
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
        ):
            value = os.environ.get(variable)
            if not value:
                continue
            base = Path(value)
            paths.update(
                str(self._join_target(base, target, variable)) for target in self.target_names
            )

    def _should_scan_metadata(self, root_name: str) -> bool:
        return root_name in _METADATA_SCAN_ROOTS

    def _collect_from_drive(
        self,
        drive_path: Path,
        paths: set[str],
        user_profile: str | None = None,
        visited: set[str] | None = None,
    ) -> None:
        visited = visited if visited is not None else set()
        for root_name in COMMON_ROOTS:
            potential_root = drive_path / root_name
            if not potential_root.exists():
                if root_name in _USER_RELATIVE_ROOTS and user_profile:
                    potential_root = Path(user_profile) / root_name
                else:
                    continue
            if not potential_root.exists():
                continue
            paths.update(
                str(self._join_target(potential_root, target, root_name))
                for target in self.target_names
            )
            self._scan_and_validate(
                potential_root,
                paths,
                depth=0,
                scan_metadata=self._should_scan_metadata(root_name),
                visited=visited,
            )

    def _scan_and_validate(
        self,
        root: Path,
        paths: set[str],
        depth: int = 0,
        scan_metadata: bool = False,
        visited: set[str] | None = None,
    ) -> None:
        if self.max_depth is not None and depth > self.max_depth:
            return
        visited = visited if visited is not None else set()
        try:
            root_key = os.path.normcase(str(root.resolve()))
        except (OSError, RuntimeError):
            return
        if root_key in visited:
            return
        visited.add(root_key)
        try:
            for item in root.iterdir():
                if item.name in _SKIP_DIRS:
                    continue
                if folder_name_matches_target(str(item), self.target_names):
                    paths.add(str(item))
                if scan_metadata and item.is_file() and item.suffix.lower() in {".exe", ".sys"}:
                    self._check_metadata(item)
                is_junction = getattr(item, "is_junction", lambda: False)
                if item.is_dir() and not item.is_symlink() and not is_junction():
                    self._scan_and_validate(item, paths, depth + 1, scan_metadata, visited)
        except (OSError, RuntimeError) as exc:
            self.skipped_count += 1
            logger.debug("FileChecker could not scan %s: %s", root, format_error(exc))

    def _check_metadata(self, path: Path) -> None:
        try:
            properties = get_file_properties(str(path))
            for ac in self.ac_database:
                if metadata_matches(properties, ac.companies, ac.products):
                    self.append_detection(
                        Detection(
                            category=CATEGORY_FOLDER,
                            text=f"METADATA MATCH: {path} ({properties.get('CompanyName')})",
                            ac_name=ac.name,
                        )
                    )
                    return
        except OSError as exc:
            self.fail_count += 1
            logger.debug("FileChecker metadata lookup failed for %s: %s", path, format_error(exc))
