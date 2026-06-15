import logging
import os
import re
from pathlib import Path
from typing import List, Set

from .base import BaseChecker
from .matchers import content_matches, metadata_matches, target_matches
from utils.attribution import resolve_ac_name
from utils.helpers import get_file_properties

logger = logging.getLogger(__name__)


class TaskChecker(BaseChecker):
    def __init__(self, ac_database, sig_index=None) -> None:
        super().__init__(ac_database, sig_index)
        self.target_names: List[str] = []
        for ac in ac_database:
            self.target_names.extend(ac.processes + ac.services)

    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        tasks_dir = Path(system_root) / "System32" / "Tasks"
        if tasks_dir.exists():
            self._scan_dir_recursive(tasks_dir)
        prefetch_dir = Path(system_root) / "Prefetch"
        if prefetch_dir.exists():
            self._collect_prefetch_metadata(prefetch_dir)

    def _append_task(self, entry: str, found_set: Set[str]) -> None:
        if entry in found_set:
            return
        found_set.add(entry)
        ac_name = resolve_ac_name(entry, self.ac_database, self.sig_index)
        self.found.append({"text": entry, "ac_name": ac_name})

    def _scan_dir_recursive(self, directory: Path) -> None:
        try:
            found_set = {item["text"] if isinstance(item, dict) else item for item in self.found}
            for item in directory.iterdir():
                if item.is_dir():
                    self._scan_dir_recursive(item)
                    continue

                triggered = False
                if target_matches(item.name, self.target_names):
                    self._append_task(f"TASK: {item.name}", found_set)
                    triggered = True
                try:
                    with open(item, "r", encoding="utf-16", errors="ignore") as f:
                        content = f.read()
                        if not triggered:
                            for target in self.target_names:
                                if content_matches(content, [target], min_length=4):
                                    self._append_task(
                                        f"TASK CONTENT MATCH: {item.name} (contains {target})",
                                        found_set,
                                    )
                                    triggered = True
                                    break
                        paths = re.findall(r'[a-zA-Z]:\\[^<>\\:"\|?*]+', content)
                        for p in paths:
                            p_clean = p.strip()
                            if os.path.exists(p_clean) and p_clean.lower().endswith((".exe", ".sys")):
                                props = get_file_properties(p_clean)
                                for ac in self.ac_database:
                                    if metadata_matches(props, ac.companies, ac.products):
                                        self._append_task(
                                            f"TASK FILE METADATA: {item.name} -> {p_clean} "
                                            f"({props.get('CompanyName')})",
                                            found_set,
                                        )
                                        break
                except Exception as e:
                    logger.debug("Failed to read task %s: %s", item.name, e)
        except Exception as e:
            logger.debug("_scan_dir_recursive %s failed: %s", directory, e)

    def _collect_prefetch_metadata(self, directory: Path) -> None:
        try:
            found_set = {item["text"] if isinstance(item, dict) else item for item in self.found}
            for item in directory.glob("*.pf"):
                fname = item.name.upper()
                for target in self.target_names:
                    t_clean = target.upper().replace(".EXE", "").replace(".SYS", "")
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", fname):
                        self._append_task(f"PREFETCH HISTORY: {item.name}", found_set)
                        break
        except Exception as e:
            logger.debug("_collect_prefetch_metadata failed: %s", e)
