<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
import logging
from typing import List, Set

import psutil

from .base import BaseChecker
from .matchers import fuzzy_matches, metadata_matches, target_matches
from utils.attribution import resolve_ac_name
from utils.helpers import batch_get_digital_signatures, get_file_hash, get_file_properties

logger = logging.getLogger(__name__)


class ProcessChecker(BaseChecker):
    def check(self) -> None:
        try:
            target_all: List[str] = []
            for ac in self.ac_database:
                target_all.extend(ac.processes)

            seen_pids: Set[int] = set()
            pending: List[dict] = []

            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    p_info = proc.info
                    pid = p_info.get("pid")
                    if pid is not None:
                        if pid in seen_pids:
                            continue
                        seen_pids.add(pid)

<<<<<<< HEAD
=======
=======
from typing import List
import psutil
from .matchers import target_matches, metadata_matches, fuzzy_matches
from utils.helpers import get_file_properties, get_file_hash, get_digital_signature
from config.signatures import AntiCheatInfo

class ProcessChecker:
    def __init__(self, ac_database: List[AntiCheatInfo]) -> None:
        self.ac_database = ac_database
        self.found: List[dict] = []

    def check(self) -> None:
        try:
            target_all = []
            for ac in self.ac_database:
                target_all.extend(ac.processes)

            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    p_info = proc.info
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                    p_name = str(p_info.get("name") or "")
                    p_exe = str(p_info.get("exe") or "")
                    p_cmdlines = p_info.get("cmdline") or []
                    p_cmdline_str = " ".join(p_cmdlines)
                    triggered = False

<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                    if (
                        target_matches(p_name, target_all)
                        or (p_exe and target_matches(p_exe, target_all))
                        or (p_cmdline_str and target_matches(p_cmdline_str, target_all))
                    ):
                        triggered = True
                        p_info["ac_name"] = resolve_ac_name(
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
<<<<<<< HEAD
=======
=======
                    if target_matches(p_name, target_all) or \
                       (p_exe and target_matches(p_exe, target_all)) or \
                       (p_cmdline_str and target_matches(p_cmdline_str, target_all)):
                        triggered = True
                        for ac in self.ac_database:
                            if target_matches(p_name, ac.processes) or \
                               (p_exe and target_matches(p_exe, ac.processes)) or \
                               (p_cmdline_str and target_matches(p_cmdline_str, ac.processes)):
                                p_info["ac_name"] = ac.name
                                break
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)

                    if not triggered and p_exe:
                        props = get_file_properties(p_exe)
                        for ac in self.ac_database:
                            if metadata_matches(props, ac.companies, ac.products):
<<<<<<< HEAD
                                p_info["triggered_by_metadata"] = (
                                    f"{props.get('CompanyName')} | {props.get('ProductName')}"
                                )
=======
<<<<<<< HEAD
                                p_info["triggered_by_metadata"] = (
                                    f"{props.get('CompanyName')} | {props.get('ProductName')}"
                                )
=======
                                p_info["triggered_by_metadata"] = f"{props.get('CompanyName')} | {props.get('ProductName')}"
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                                p_info["ac_name"] = ac.name
                                triggered = True
                                break

                    if not triggered:
                        for ac in self.ac_database:
                            match_found = False
                            for target in ac.processes:
                                if fuzzy_matches(p_name, target, threshold=0.85):
<<<<<<< HEAD
                                    p_info["triggered_by_fuzzy"] = (
                                        f"Fuzzy match: {p_name} ~ {target}"
                                    )
=======
<<<<<<< HEAD
                                    p_info["triggered_by_fuzzy"] = (
                                        f"Fuzzy match: {p_name} ~ {target}"
                                    )
=======
                                    p_info["triggered_by_fuzzy"] = f"Fuzzy match: {p_name} ~ {target}"
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                                    p_info["ac_name"] = ac.name
                                    triggered = True
                                    match_found = True
                                    break
                            if match_found:
                                break

                    if triggered:
<<<<<<< HEAD
                        pending.append(p_info)
=======
<<<<<<< HEAD
                        pending.append(p_info)
=======
                        if p_info not in self.found:
                            if p_exe:
                                p_info["metadata"] = get_file_properties(p_exe)
                                p_info["sha256"] = get_file_hash(p_exe)
                                p_info["signature"] = get_digital_signature(p_exe)
                            self.found.append(p_info)
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                        continue

                    try:
                        for module in proc.memory_maps(grouped=False):
                            m_path = str(module.path)
                            if target_matches(m_path, target_all):
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                                p_info["triggered_by_module"] = m_path
                                p_info["ac_name"] = resolve_ac_name(
                                    m_path,
                                    self.ac_database,
                                    self.sig_index,
                                    include_services=False,
                                )
                                pending.append(p_info)
                                break
<<<<<<< HEAD
=======
=======
                                if p_info not in self.found:
                                    p_info["triggered_by_module"] = m_path
                                    self.found.append(p_info)
                                    break
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 979330d (update 2026-06-15 16:33:37)

            exe_paths = list({str(p.get("exe")) for p in pending if p.get("exe")})
            signatures = batch_get_digital_signatures(exe_paths)

            for p_info in pending:
                p_exe = str(p_info.get("exe") or "")
                if p_exe:
                    p_info["metadata"] = get_file_properties(p_exe)
                    p_info["sha256"] = get_file_hash(p_exe)
                    p_info["signature"] = signatures.get(p_exe, "")
                self.found.append(p_info)

        except Exception as e:
            logger.debug("ProcessChecker failed: %s", e)
<<<<<<< HEAD
=======
=======
        except Exception:
            pass
>>>>>>> e285a17f27e49403e5e4eb37a3f873a4bc5e00ae
>>>>>>> 979330d (update 2026-06-15 16:33:37)
