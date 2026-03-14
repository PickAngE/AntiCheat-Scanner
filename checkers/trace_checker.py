import os
import re
import subprocess
from typing import List
from .matchers import target_matches, content_matches
class TraceChecker:
    def __init__(self, target_names: List[str]) -> None:
        self.target_names = target_names
        self.found: List[str] = []
    def check(self) -> None:
        self._check_dns_cache()
        self._check_env_vars()
        self._check_wmi_drivers()
        self._check_named_pipes()
        self._check_filter_drivers()
        self._check_event_logs()
        self._check_defender_exclusions()
        self._check_firewall_rules()
        self._check_bam()
        self._check_boot_config()
        self._check_netstat()
        self._check_driverquery()
    def _clean_target(self, target: str) -> str:
        return target.lower().replace(".exe", "").replace(".sys", "").replace(".dll", "").strip()
    def _check_dns_cache(self) -> None:
        try:
            output = subprocess.check_output(
                ["ipconfig", "/displaydns"], text=True, errors="ignore", timeout=15
            )
            for target in self.target_names:
                t_clean = self._clean_target(target)
                if len(t_clean) < 4:
                    continue
                if re.search(rf"\b{re.escape(t_clean)}\b", output.lower()):
                    self.found.append(f"DNS CACHE: Trace related to {t_clean}")
        except Exception:
            pass
    def _check_env_vars(self) -> None:
        try:
            for key, value in os.environ.items():
                combined = f"{key} {value}".lower()
                for target in self.target_names:
                    t_clean = self._clean_target(target)
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", combined):
                        self.found.append(f"ENV VAR: {key}={value}")
        except Exception:
            pass
    def _check_wmi_drivers(self) -> None:
        try:
            output = subprocess.check_output(
                ["wmic", "sysdriver", "get", "name,displayname"],
                text=True, errors="ignore", timeout=30,
            )
            for line in output.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if target_matches(stripped, self.target_names):
                    self.found.append(f"WMI DRIVER TRACE: {stripped}")
        except Exception:
            pass
    def _check_named_pipes(self) -> None:
        try:
            pipes = os.listdir(r"\\.\pipe")
            for pipe_name in pipes:
                for target in self.target_names:
                    t_clean = self._clean_target(target)
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", pipe_name.lower()):
                        entry = f"NAMED PIPE: \\\\.\\pipe\\{pipe_name}"
                        if entry not in self.found:
                            self.found.append(entry)
                        break
        except Exception:
            pass
    def _check_filter_drivers(self) -> None:
        try:
            output = subprocess.check_output(
                ["fltmc", "instances"], text=True, errors="ignore", timeout=15
            )
            for line in output.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                for target in self.target_names:
                    t_clean = self._clean_target(target)
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", stripped.lower()):
                        entry = f"FILTER DRIVER: {stripped}"
                        if entry not in self.found:
                            self.found.append(entry)
                        break
        except Exception:
            pass
    def _check_event_logs(self) -> None:
        try:
            output = subprocess.check_output(
                [
                    "wevtutil", "qe", "System",
                    "/q:*[System[Provider[@Name='Service Control Manager']]]",
                    "/f:text", "/c:300", "/rd:true",
                ],
                text=True, errors="ignore", timeout=30,
            )
            output_lower = output.lower()
            for target in self.target_names:
                t_clean = self._clean_target(target)
                if len(t_clean) < 4:
                    continue
                if re.search(rf"\b{re.escape(t_clean)}\b", output_lower):
                    entry = f"EVENT LOG: System log contains trace of {target}"
                    if entry not in self.found:
                        self.found.append(entry)
        except Exception:
            pass
    def _check_defender_exclusions(self) -> None:
        try:
            import winreg
            paths_to_check = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"),
            ]
            for hive, subkey in paths_to_check:
                try:
                    handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(handle)[1]
                    for i in range(num_values):
                        try:
                            val_name, _, _ = winreg.EnumValue(handle, i)
                            for target in self.target_names:
                                t_clean = self._clean_target(target)
                                if len(t_clean) < 4:
                                    continue
                                if re.search(rf"\b{re.escape(t_clean)}\b", val_name.lower()):
                                    entry = f"DEFENDER EXCLUSION: {val_name}"
                                    if entry not in self.found:
                                        self.found.append(entry)
                                    break
                        except OSError:
                            continue
                    winreg.CloseKey(handle)
                except (FileNotFoundError, OSError):
                    continue
        except Exception:
            pass
    def _check_firewall_rules(self) -> None:
        try:
            output = subprocess.check_output(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
                text=True, errors="ignore", timeout=30,
            )
            output_lower = output.lower()
            for target in self.target_names:
                t_clean = self._clean_target(target)
                if len(t_clean) < 4:
                    continue
                if re.search(rf"\b{re.escape(t_clean)}\b", output_lower):
                    entry = f"FIREWALL RULE: Inbound rule related to {target}"
                    if entry not in self.found:
                        self.found.append(entry)
        except Exception:
            pass
    def _check_bam(self) -> None:
        try:
            import winreg
            bam_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            try:
                bam_root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path)
            except FileNotFoundError:
                bam_path = r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"
                try:
                    bam_root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path)
                except FileNotFoundError:
                    return
            for i in range(winreg.QueryInfoKey(bam_root)[0]):
                try:
                    sid = winreg.EnumKey(bam_root, i)
                    sid_key = winreg.OpenKey(bam_root, sid)
                    num_values = winreg.QueryInfoKey(sid_key)[1]
                    for j in range(num_values):
                        try:
                            val_name, _, _ = winreg.EnumValue(sid_key, j)
                            val_lower = val_name.lower()
                            for target in self.target_names:
                                t_clean = self._clean_target(target)
                                if len(t_clean) < 4:
                                    continue
                                if re.search(rf"\b{re.escape(t_clean)}\b", val_lower):
                                    entry = f"BAM EXECUTION: {val_name}"
                                    if entry not in self.found:
                                        self.found.append(entry)
                                    break
                        except OSError:
                            continue
                    winreg.CloseKey(sid_key)
                except OSError:
                    continue
            winreg.CloseKey(bam_root)
        except Exception:
            pass
    def _check_boot_config(self) -> None:
        try:
            output = subprocess.check_output(
                ["bcdedit", "/enum", "all"],
                text=True, errors="ignore", timeout=15,
            )
            output_lower = output.lower()
            for target in self.target_names:
                t_clean = self._clean_target(target)
                if len(t_clean) < 4:
                    continue
                if re.search(rf"\b{re.escape(t_clean)}\b", output_lower):
                    entry = f"BOOT CONFIG: Boot entry related to {target}"
                    if entry not in self.found:
                        self.found.append(entry)
        except Exception:
            pass
    def _check_netstat(self) -> None:
        try:
            output = subprocess.check_output(
                ["netstat", "-anob"], text=True, errors="ignore", timeout=30
            )
            output_lower = output.lower()
            for target in self.target_names:
                t_clean = self._clean_target(target)
                if len(t_clean) < 4:
                    continue
                if re.search(rf"\b{re.escape(t_clean)}\b", output_lower):
                    entry = f"NETWORK: Active connection or listener for {target}"
                    if entry not in self.found:
                        self.found.append(entry)
        except Exception:
            pass
    def _check_driverquery(self) -> None:
        try:
            output = subprocess.check_output(
                ["driverquery", "/v", "/fo", "csv"], text=True, errors="ignore", timeout=30
            )
            lines = output.splitlines()
            if not lines: return
            for line in lines[1:]:
                line_lower = line.lower()
                for target in self.target_names:
                    t_clean = self._clean_target(target)
                    if len(t_clean) < 4:
                        continue
                    if re.search(rf"\b{re.escape(t_clean)}\b", line_lower):
                        entry = f"DRIVERQUERY: Active loaded driver matching {target} - {line.split(',')[0].strip('\"')} "
                        if entry not in self.found:
                            self.found.append(entry)
                        break
        except Exception:
            pass
