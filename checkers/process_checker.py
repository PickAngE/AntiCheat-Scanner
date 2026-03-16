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
                    p_name = str(p_info.get("name") or "")
                    p_exe = str(p_info.get("exe") or "")
                    p_cmdlines = p_info.get("cmdline") or []
                    p_cmdline_str = " ".join(p_cmdlines)
                    triggered = False

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

                    if not triggered and p_exe:
                        props = get_file_properties(p_exe)
                        for ac in self.ac_database:
                            if metadata_matches(props, ac.companies, ac.products):
                                p_info["triggered_by_metadata"] = f"{props.get('CompanyName')} | {props.get('ProductName')}"
                                p_info["ac_name"] = ac.name
                                triggered = True
                                break

                    if not triggered:
                        for ac in self.ac_database:
                            match_found = False
                            for target in ac.processes:
                                if fuzzy_matches(p_name, target, threshold=0.85):
                                    p_info["triggered_by_fuzzy"] = f"Fuzzy match: {p_name} ~ {target}"
                                    p_info["ac_name"] = ac.name
                                    triggered = True
                                    match_found = True
                                    break
                            if match_found:
                                break

                    if triggered:
                        if p_info not in self.found:
                            if p_exe:
                                p_info["metadata"] = get_file_properties(p_exe)
                                p_info["sha256"] = get_file_hash(p_exe)
                                p_info["signature"] = get_digital_signature(p_exe)
                            self.found.append(p_info)
                        continue

                    try:
                        for module in proc.memory_maps(grouped=False):
                            m_path = str(module.path)
                            if target_matches(m_path, target_all):
                                if p_info not in self.found:
                                    p_info["triggered_by_module"] = m_path
                                    self.found.append(p_info)
                                    break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
