import logging
import os
import re
from pathlib import Path
from typing import List, Optional

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex

from .base import BaseChecker
from .detection import CATEGORY_TASK, Detection
from .matchers import content_matches, metadata_matches, target_matches
from utils.attribution import resolve_ac_name
from utils.helpers import get_file_properties

logger = logging.getLogger(__name__)


class TaskChecker(BaseChecker):
    CATEGORY = CATEGORY_TASK

    def __init__(
        self,
        ac_database: List[AntiCheatInfo],
        sig_index: Optional[SignatureIndex] = None,
    ) -> None:
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

    def _append_task(self, entry: str) -> None:
        ac_name = resolve_ac_name(entry, self.ac_database, self.sig_index)
        self.append_detection(Detection(
            category=CATEGORY_TASK, text=entry, ac_name=ac_name,
        ))

    def _scan_dir_recursive(self, directory: Path) -> None:
        try:
            for item in directory.iterdir():
                try:
                    if item.is_dir():
                        self._scan_dir_recursive(item)
                        continue

                    triggered = False
                    if target_matches(item.name, self.target_names):
                        self._append_task(f"TASK: {item.name}")
                        triggered = True
                    try:
                        with open(item, "r", encoding="utf-16", errors="ignore") as f:
                            content = f.read()
                            if not triggered:
                                for target in self.target_names:
                                    if content_matches(content, [target], min_length=4):
                                        self._append_task(
                                            f"TASK CONTENT MATCH: {item.name} (contains {target})",
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
                                            )
                                            break
                    except Exception as e:
                        logger.debug("Failed to read task %s: %s", item.name, e)
                except Exception as e:
                    self.fail_count += 1
                    logger.error(
                        "TaskChecker: unexpected error on %s: %s",
                        item, e, exc_info=True,
                    )
                    continue
        except Exception as e:
            logger.error("%s failed", type(self).__name__, exc_info=True)

    def _collect_prefetch_metadata(self, directory: Path) -> None:
        try:
            for item in directory.glob("*.pf"):
                fname = item.name.upper()
                for target in self.target_names:
                    t_clean = target.upper().replace(".EXE", "").replace(".SYS", "")
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", fname):
                        self._append_task(f"PREFETCH HISTORY: {item.name}")
                        break
        except Exception as e:
            logger.debug("_collect_prefetch_metadata failed: %s", e)
