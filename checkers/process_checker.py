from __future__ import annotations

import logging
from typing import Any, ClassVar

import psutil

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_PROC, Detection
from checkers.matchers import metadata_matches, target_matches
from utils.attribution import resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)


class ProcessChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_PROC

    def check(self) -> None:
        target_all = [name for ac in self.ac_database for name in ac.processes]
        target_bases = {
            name.casefold().removesuffix(".exe").removesuffix(".sys").removesuffix(".dll")
            for ac in self.ac_database
            for name in ac.processes
        }
        target_bases = {name for name in target_bases if len(name) >= 3}
        seen_pids: set[int] = set()
        pending: list[Detection] = []

        for process in psutil.process_iter(["pid", "name", "exe"]):
            pid: int | None = None
            try:
                process_info: dict[str, Any] = process.info
                pid_value = process_info.get("pid")
                pid = int(pid_value) if pid_value is not None else None
                if pid is not None:
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                process_name = str(process_info.get("name") or "")
                executable = str(process_info.get("exe") or "")
                might_match = False
                if self.sig_index is not None:
                    might_match = bool(
                        self.sig_index.lookup(process_name)
                        or (executable and self.sig_index.lookup(executable))
                    )
                if not might_match:
                    combined = f"{process_name} {executable}".casefold()
                    might_match = any(base in combined for base in target_bases)

                triggered = False
                ac_name: str | None = None
                if might_match and (
                    target_matches(process_name, target_all)
                    or (executable and target_matches(executable, target_all))
                ):
                    triggered = True
                    ac_name = resolve_ac_name(
                        process_name,
                        self.ac_database,
                        self.sig_index,
                        include_drivers=False,
                    ) or resolve_ac_name(
                        executable,
                        self.ac_database,
                        self.sig_index,
                        include_drivers=False,
                    )

                if not triggered and executable:
                    properties = get_file_properties(executable)
                    for ac in self.ac_database:
                        if metadata_matches(properties, ac.companies, ac.products):
                            triggered = True
                            ac_name = ac.name
                            break

                if triggered:
                    pending.append(
                        Detection(
                            category=CATEGORY_PROC,
                            text=process_name or executable,
                            ac_name=ac_name,
                            active=True,
                            raw=process_info,
                        )
                    )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except (OSError, TypeError, ValueError) as exc:
                self.fail_count += 1
                logger.error("ProcessChecker could not inspect pid %s: %s", pid, format_error(exc))

        executable_paths = sorted(
            {
                str(detection.raw.get("exe"))
                for detection in pending
                if isinstance(detection.raw, dict) and detection.raw.get("exe")
            }
        )
        signatures = batch_get_digital_signatures(executable_paths)
        for detection in pending:
            executable = (
                str(detection.raw.get("exe") or "") if isinstance(detection.raw, dict) else ""
            )
            if executable:
                detection.tech = {
                    "name": detection.raw.get("name", detection.text),
                    "path": executable,
                    "sha": get_file_hash(executable),
                    "sig": signatures.get(executable, ""),
                    "meta": get_file_properties(executable),
                    "state": "running",
                }
            self.append_detection(detection)
