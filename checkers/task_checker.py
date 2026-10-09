from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_TASK, Detection
from checkers.matchers import (
    compile_combined_pattern,
    metadata_matches,
    strip_binary_suffix,
    target_matches,
)
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_name
from utils.helpers import get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)




_WINDOWS_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\|\\\\|%[^%\r\n]+%\\)(?:[^<>:\"|?*\r\n]+\\)*[^<>:\"|?*\r\n]*"
    r"\.(?:exe|sys|dll|bat|ps1|vbs)\b",
    re.IGNORECASE,
)



_METADATA_EXTENSIONS = frozenset({".exe", ".sys", ".dll"})



_TASK_SCAN_MAX_DEPTH = 20


@lru_cache(maxsize=4096)
def _exists_cached(path: str) -> bool:



    return os.path.exists(path)


def clear_exists_cache() -> None:
    _exists_cached.cache_clear()


def _resolve_task_path(raw_path: str) -> str:
    expanded = os.path.expandvars(raw_path.strip().strip("\"'"))
    return os.path.normpath(expanded)


def _read_task_content(item: Path) -> str | None:
    try:
        return item.read_text(encoding="utf-16", errors="strict")
    except (OSError, UnicodeError):
        pass
    try:
        return item.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        pass
    try:
        return item.read_bytes().decode("utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return None


class TaskChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_TASK

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self.target_names = [
            name
            for ac in ac_database
            for name in ac.processes + ac.services + ac.drivers + ac.products
        ]
        self._content_pattern = compile_combined_pattern(self.target_names)
        self._prefetch_pattern = compile_combined_pattern(
            [strip_binary_suffix(name) for name in self.target_names]
        )

    def check(self) -> None:
        clear_exists_cache()
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        tasks_directory = Path(system_root) / "System32" / "Tasks"
        if tasks_directory.exists():
            self._scan_directory(tasks_directory)
        prefetch_directory = Path(system_root) / "Prefetch"
        if prefetch_directory.exists():
            self._collect_prefetch(prefetch_directory)

    def _append_task(self, entry: str, ac_name: str | None = None) -> None:
        resolved_name = ac_name or resolve_ac_name(
            entry,
            self.ac_database,
            self.sig_index,
            include_products=True,
            include_name=True,
        )
        self.append_detection(Detection(category=CATEGORY_TASK, text=entry, ac_name=resolved_name))

    def _scan_directory(self, directory: Path) -> None:
        stack: list[tuple[Path, int]] = [(directory, 0)]
        visited: set[str] = set()
        while stack:
            current_dir, depth = stack.pop()
            if depth > _TASK_SCAN_MAX_DEPTH:
                continue
            try:
                dir_key = os.path.normcase(str(current_dir.resolve()))
            except (OSError, RuntimeError):
                continue
            if dir_key in visited:
                continue
            visited.add(dir_key)
            try:
                entries = list(current_dir.iterdir())
            except OSError as exc:
                self.fail_count += 1
                logger.error("TaskChecker could not scan %s: %s", current_dir, format_error(exc))
                continue
            for item in entries:
                try:
                    try:
                        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
                            continue
                    except (OSError, RuntimeError):
                        continue
                    if item.is_dir():
                        stack.append((item, depth + 1))
                        continue
                    triggered = False
                    if target_matches(item.name, self.target_names):
                        self._append_task(f"TASK: {item.name}")
                        triggered = True
                    content = _read_task_content(item)
                    if content is None:
                        self.fail_count += 1
                        logger.debug("TaskChecker could not read %s", item)
                        continue
                    if not triggered and self._content_pattern.search(content):
                        match = self._content_pattern.search(content)
                        token = match.group(0) if match else "?"
                        self._append_task(f"TASK CONTENT MATCH: {item.name} (contains {token})")
                        triggered = True
                    for match in _WINDOWS_PATH_PATTERN.finditer(content):
                        raw_path = match.group(0).strip()
                        path = _resolve_task_path(raw_path)
                        if not path.lower().endswith(tuple(_METADATA_EXTENSIONS)):
                            continue
                        if not _exists_cached(path):
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

    def _collect_prefetch(self, directory: Path) -> None:
        try:
            for item in directory.glob("*.pf"):
                filename = item.name.casefold()
                if self._prefetch_pattern.search(filename):
                    self._append_task(f"PREFETCH HISTORY: {item.name}")
        except OSError as exc:
            self.fail_count += 1
            logger.error("Prefetch scan failed: %s", format_error(exc))
