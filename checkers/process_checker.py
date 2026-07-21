import logging
from typing import List, Set

import psutil

from .base import BaseChecker
from .detection import CATEGORY_PROC, Detection
from .matchers import fuzzy_matches, metadata_matches, target_matches
from utils.attribution import resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties

logger = logging.getLogger(__name__)


class ProcessChecker(BaseChecker):
    CATEGORY = CATEGORY_PROC

    def check(self) -> None:
        try:
            target_all: List[str] = []
            target_bases: set[str] = set()
            for ac in self.ac_database:
                target_all.extend(ac.processes)
                for target in ac.processes:
                    base = target.lower().replace(".exe", "").replace(".sys", "").strip()
                    if len(base) >= 3:
                        target_bases.add(base)

            seen_pids: Set[int] = set()
            pending: List[Detection] = []

            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    p_info = proc.info
                    pid = p_info.get("pid")
                    if pid is not None:
                        if pid in seen_pids:
                            continue
                        seen_pids.add(pid)

                    p_name = str(p_info.get("name") or "")
                    p_exe = str(p_info.get("exe") or "")
                    p_cmdlines = p_info.get("cmdline") or []
                    p_cmdline_str = " ".join(p_cmdlines)

                    might_match = False
                    if self.sig_index is not None:
                        if self.sig_index.lookup(p_name) or (p_exe and self.sig_index.lookup(p_exe)):
                            might_match = True
                    if not might_match:
                        combined = f"{p_name} {p_exe} {p_cmdline_str}".lower()
                        might_match = any(base in combined for base in target_bases)

                    triggered = False
                    ac_name = None

                    if might_match and (
                        target_matches(p_name, target_all)
                        or (p_exe and target_matches(p_exe, target_all))
                        or (p_cmdline_str and target_matches(p_cmdline_str, target_all))
                    ):
                        triggered = True
                        ac_name = resolve_ac_name(
                            p_name,
                            self.ac_database,
                            self.sig_index,
                            include_drivers=False,
                        ) or resolve_ac_name(
                            p_exe,
                            self.ac_database,
                            self.sig_index,
                            include_drivers=False,
                        )

                    if not triggered and p_exe:
                        props = get_file_properties(p_exe)
                        for ac in self.ac_database:
                            if metadata_matches(props, ac.companies, ac.products):
                                triggered = True
                                ac_name = ac.name
                                break

                    if not triggered:
                        for ac in self.ac_database:
                            match_found = False
                            for target in ac.processes:
                                if fuzzy_matches(p_name, target, threshold=0.85):
                                    triggered = True
                                    ac_name = ac.name
                                    match_found = True
                                    break
                            if match_found:
                                break

                    if triggered:
                        pending.append(Detection(
                            category=CATEGORY_PROC,
                            text=p_name,
                            ac_name=ac_name,
                            active=True,
                            raw=p_info,
                        ))

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            exe_paths = list({str(d.raw.get("exe")) for d in pending if d.raw and d.raw.get("exe")})
            signatures = batch_get_digital_signatures(exe_paths)

            for det in pending:
                p_exe = str(det.raw.get("exe") or "") if det.raw else ""
                if p_exe:
                    det.tech = {
                        "name": det.raw.get("name", ""),
                        "path": p_exe,
                        "sha": get_file_hash(p_exe),
                        "sig": signatures.get(p_exe, ""),
                        "meta": get_file_properties(p_exe),
                    }
                self.found.append(det)

        except Exception as e:
            logger.debug("ProcessChecker failed: %s", e)
