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

                    p_name = str(p_info.get("name") or "")
                    p_exe = str(p_info.get("exe") or "")
                    p_cmdlines = p_info.get("cmdline") or []
                    p_cmdline_str = " ".join(p_cmdlines)
                    triggered = False

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

                    if not triggered and p_exe:
                        props = get_file_properties(p_exe)
                        for ac in self.ac_database:
                            if metadata_matches(props, ac.companies, ac.products):
                                p_info["triggered_by_metadata"] = (
                                    f"{props.get('CompanyName')} | {props.get('ProductName')}"
                                )
                                p_info["ac_name"] = ac.name
                                triggered = True
                                break

                    if not triggered:
                        for ac in self.ac_database:
                            match_found = False
                            for target in ac.processes:
                                if fuzzy_matches(p_name, target, threshold=0.85):
                                    p_info["triggered_by_fuzzy"] = (
                                        f"Fuzzy match: {p_name} ~ {target}"
                                    )
                                    p_info["ac_name"] = ac.name
                                    triggered = True
                                    match_found = True
                                    break
                            if match_found:
                                break

                    if triggered:
                        pending.append(p_info)
                        continue

                    try:
                        for module in proc.memory_maps(grouped=False):
                            m_path = str(module.path)
                            if target_matches(m_path, target_all):
                                p_info["triggered_by_module"] = m_path
                                p_info["ac_name"] = resolve_ac_name(
                                    m_path,
                                    self.ac_database,
                                    self.sig_index,
                                    include_services=False,
                                )
                                pending.append(p_info)
                                break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

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
