import os
import re
from pathlib import Path
from typing import List
from .matchers import target_matches, content_matches, metadata_matches
from utils.helpers import get_file_properties
from config.signatures import AntiCheatInfo
class TaskChecker:
    def __init__(self, ac_database: List[AntiCheatInfo]) -> None:
        self.ac_database = ac_database
        self.target_names = []
        for ac in ac_database:
            self.target_names.extend(ac.processes + ac.services)
        self.found: List[str] = []
    def check(self) -> None:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        tasks_dir = Path(system_root) / "System32" / "Tasks"
        if not tasks_dir.exists():
            return
        self._scan_dir_recursive(tasks_dir)
        prefetch_dir = Path(system_root) / "Prefetch"
        if prefetch_dir.exists():
            self._collect_prefetch_metadata(prefetch_dir)
    def _scan_dir_recursive(self, directory: Path) -> None:
        try:
            for item in directory.iterdir():
                if item.is_dir():
                    self._scan_dir_recursive(item)
                else:
                    triggered = False
                    if target_matches(item.name, self.target_names):
                        self.found.append(f"TASK: {item.name}")
                        triggered = True
                    try:
                        with open(item, "r", encoding="utf-16", errors="ignore") as f:
                            content = f.read()
                            if not triggered:
                                for target in self.target_names:
                                    t_base = target.lower().replace(".exe", "").replace(".sys", "")
                                    if len(t_base) < 4:
                                        continue
                                    if content_matches(content, [target], min_length=4):
                                        self.found.append(f"TASK CONTENT MATCH: {item.name} (contains {target})")
                                        triggered = True
                                        break
                            paths = re.findall(r'[a-zA-Z]:\\[^<>\\:"\|?*]+', content)
                            for p in paths:
                                p_clean = p.strip()
                                if os.path.exists(p_clean) and p_clean.lower().endswith(('.exe', '.sys')):
                                    props = get_file_properties(p_clean)
                                    for ac in self.ac_database:
                                        if metadata_matches(props, ac.companies, ac.products):
                                            self.found.append(f"TASK FILE METADATA: {item.name} -> {p_clean} ({props.get('CompanyName')})")
                                            break
                    except Exception:
                        pass
        except Exception:
            pass
    def _collect_prefetch_metadata(self, directory: Path) -> None:
        try:
            for item in directory.glob("*.pf"):
                fname = item.name.upper()
                for target in self.target_names:
                    t_clean = target.upper().replace(".EXE", "").replace(".SYS", "")
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", fname):
                        self.found.append(f"PREFETCH HISTORY: {item.name}")
                        break
        except Exception:
            pass
