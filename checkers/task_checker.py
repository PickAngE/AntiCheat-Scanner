from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_TASK, Detection
from checkers.matchers import content_matches, metadata_matches, target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_name
from utils.helpers import get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)

_WINDOWS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\(?:[^<>:\"|?*\r\n]+\\)*[^<>:\"|?*\r\n]*\.(?:exe|sys)\b",
    re.IGNORECASE,
)


class TaskChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_TASK

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self.target_names = [name for ac in ac_database for name in ac.processes + ac.services]

    def check(self) -> None:
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        tasks_directory = Path(system_root) / "System32" / "Tasks"
        if tasks_directory.exists():
            self._scan_directory(tasks_directory)
        prefetch_directory = Path(system_root) / "Prefetch"
        if prefetch_directory.exists():
            self._collect_prefetch(prefetch_directory)

    def _append_task(self, entry: str, ac_name: str | None = None) -> None:
        resolved_name = ac_name or resolve_ac_name(entry, self.ac_database, self.sig_index)
        self.append_detection(Detection(category=CATEGORY_TASK, text=entry, ac_name=resolved_name))

    def _scan_directory(self, directory: Path) -> None:
        try:
            for item in directory.iterdir():
                try:
                    if item.is_dir():
                        self._scan_directory(item)
                        continue
                    triggered = False
                    if target_matches(item.name, self.target_names):
                        self._append_task(f"TASK: {item.name}")
                        triggered = True
                    try:
                        content = item.read_text(encoding="utf-16", errors="ignore")
                    except (OSError, UnicodeError) as exc:
                        self.fail_count += 1
                        logger.debug("TaskChecker could not read %s: %s", item, format_error(exc))
                        continue
                    if not triggered:
                        for target in self.target_names:
                            if content_matches(content, [target]):
                                self._append_task(
                                    f"TASK CONTENT MATCH: {item.name} (contains {target})"
                                )
                                triggered = True
                                break
                    for match in _WINDOWS_PATH_PATTERN.finditer(content):
                        path = match.group(0).strip()
                        if not os.path.exists(path) or not path.lower().endswith((".exe", ".sys")):
                            continue
                        properties = get_file_properties(path)
                        for ac in self.ac_database:
                            if metadata_matches(properties, ac.companies, ac.products):
                                self._append_task(
                                    f"TASK FILE METADATA: {item.name} -> {path} "
                                    f"({properties.get('CompanyName')})",
                                    ac.name,
                                )
                                break
                except OSError as exc:
                    self.fail_count += 1
                    logger.error("TaskChecker could not inspect %s: %s", item, format_error(exc))
        except OSError as exc:
            self.fail_count += 1
            logger.error("TaskChecker could not scan %s: %s", directory, format_error(exc))

    def _collect_prefetch(self, directory: Path) -> None:
        try:
            for item in directory.glob("*.pf"):
                filename = item.name.casefold()
                for target in self.target_names:
                    normalized = target.casefold()
                    for extension in (".exe", ".sys"):
                        if normalized.endswith(extension):
                            normalized = normalized[: -len(extension)]
                            break
                    if len(normalized) >= 3 and re.search(
                        rf"\b{re.escape(normalized)}\b",
                        filename,
                    ):
                        self._append_task(f"PREFETCH HISTORY: {item.name}")
                        break
        except OSError as exc:
            self.fail_count += 1
            logger.error("Prefetch scan failed: %s", format_error(exc))
