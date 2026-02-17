from typing import List

import psutil

from .matchers import target_matches


class ProcessChecker:
    def __init__(self, target_processes: List[str]) -> None:
        self.target_processes = target_processes
        self.found: List[dict] = []

    def check(self) -> None:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
                try:
                    p_name = proc.info.get("name") or ""
                    found_match = target_matches(p_name, self.target_processes)
                    if found_match:
                        self.found.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
