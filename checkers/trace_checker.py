import logging
import os
import re
import csv
import subprocess
from typing import List

from .base import BaseChecker
from .matchers import target_matches
from utils.attribution import resolve_ac_name

logger = logging.getLogger(__name__)


class TraceChecker(BaseChecker):
    def __init__(self, ac_database, sig_index=None) -> None:
        super().__init__(ac_database, sig_index)
        self._target_names: List[str] = []
        for ac in ac_database:
            self._target_names.extend(ac.services + ac.processes + ac.drivers)
        self._pattern = None

    def _get_combined_pattern(self):
        if self._pattern is None:
            clean = [self._clean_target(t) for t in self._target_names]
            clean = list(dict.fromkeys(c for c in clean if len(c) >= 4))
            if clean:
                self._pattern = re.compile(
                    r"\b(?:" + "|".join(re.escape(c) for c in clean) + r")\b",
                    re.IGNORECASE,
                )
            else:
                self._pattern = re.compile(r"(?!)")
        return self._pattern

    def _clean_target(self, target: str) -> str:
        return target.lower().replace(".exe", "").replace(".sys", "").replace(".dll", "").strip()

    def _append_trace(self, text: str, active: bool = False) -> None:
        existing = {item["text"] for item in self.found if isinstance(item, dict)}
        if text in existing:
            return
        ac_name = resolve_ac_name(text, self.ac_database, self.sig_index)
        self.found.append({"text": text, "ac_name": ac_name, "active": active})

    def check(self) -> None:
        self._get_combined_pattern()
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

    def _check_dns_cache(self) -> None:
        try:
            output = subprocess.check_output(
                ["ipconfig", "/displaydns"], text=True, errors="ignore", timeout=15
            )
            m = self._pattern.search(output.lower())
            if m:
                self._append_trace(f"DNS CACHE: Trace related to {m.group()}")
        except Exception as e:
            logger.debug("_check_dns_cache failed: %s", e)

    def _check_env_vars(self) -> None:
        try:
            for key, value in os.environ.items():
                combined = f"{key} {value}"
                if self._pattern.search(combined):
                    self._append_trace(f"ENV VAR: {key}={value}")
        except Exception as e:
            logger.debug("_check_env_vars failed: %s", e)

    def _check_wmi_drivers(self) -> None:
        try:
            output = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_SystemDriver | "
                    "Select-Object Name,DisplayName | Format-Table -AutoSize -HideTableHeaders",
                ],
                text=True,
                errors="ignore",
                timeout=30,
            )
            for line in output.splitlines():
                stripped = line.strip()
                if stripped and target_matches(stripped, self._target_names):
                    self._append_trace(f"WMI DRIVER TRACE: {stripped}")
        except Exception as e:
            logger.debug("_check_wmi_drivers failed: %s", e)

    def _check_named_pipes(self) -> None:
        try:
            existing = {item["text"] for item in self.found if isinstance(item, dict)}
            for pipe_name in os.listdir(r"\\.\pipe"):
                if self._pattern.search(pipe_name):
                    entry = f"NAMED PIPE: \\\\.\\pipe\\{pipe_name}"
                    if entry not in existing:
                        existing.add(entry)
                        self._append_trace(entry)
        except Exception as e:
            logger.debug("_check_named_pipes failed: %s", e)

    def _check_filter_drivers(self) -> None:
        try:
            output = subprocess.check_output(
                ["fltmc", "instances"], text=True, errors="ignore", timeout=15
            )
            existing = {item["text"] for item in self.found if isinstance(item, dict)}
            for line in output.splitlines():
                stripped = line.strip()
                if stripped and self._pattern.search(stripped):
                    entry = f"FILTER DRIVER: {stripped}"
                    if entry not in existing:
                        existing.add(entry)
                        self._append_trace(entry, active=True)
        except Exception as e:
            logger.debug("_check_filter_drivers failed: %s", e)

    def _check_event_logs(self) -> None:
        try:
            output = subprocess.check_output(
                [
                    "wevtutil",
                    "qe",
                    "System",
                    "/q:*[System[Provider[@Name='Service Control Manager']]]",
                    "/f:text",
                    "/c:300",
                    "/rd:true",
                ],
                text=True,
                errors="ignore",
                timeout=30,
            )
            m = self._pattern.search(output)
            if m:
                self._append_trace(f"EVENT LOG: System log contains trace of {m.group()}")
        except Exception as e:
            logger.debug("_check_event_logs failed: %s", e)

    def _check_defender_exclusions(self) -> None:
        try:
            import winreg

            paths_to_check = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"),
            ]
            existing = {item["text"] for item in self.found if isinstance(item, dict)}
            for hive, subkey in paths_to_check:
                try:
                    handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                    num_values = winreg.QueryInfoKey(handle)[1]
                    for i in range(num_values):
                        try:
                            val_name, _, _ = winreg.EnumValue(handle, i)
                            if self._pattern.search(val_name):
                                entry = f"DEFENDER EXCLUSION: {val_name}"
                                if entry not in existing:
                                    existing.add(entry)
                                    self._append_trace(entry)
                        except OSError:
                            continue
                    winreg.CloseKey(handle)
                except (FileNotFoundError, OSError):
                    continue
        except Exception as e:
            logger.debug("_check_defender_exclusions failed: %s", e)

    def _check_firewall_rules(self) -> None:
        try:
            output = subprocess.check_output(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
                text=True,
                errors="ignore",
                timeout=30,
            )
            m = self._pattern.search(output)
            if m:
                self._append_trace(f"FIREWALL RULE: Inbound rule related to {m.group()}")
        except Exception as e:
            logger.debug("_check_firewall_rules failed: %s", e)

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

            existing = {item["text"] for item in self.found if isinstance(item, dict)}
            for i in range(winreg.QueryInfoKey(bam_root)[0]):
                try:
                    sid = winreg.EnumKey(bam_root, i)
                    sid_key = winreg.OpenKey(bam_root, sid)
                    num_values = winreg.QueryInfoKey(sid_key)[1]
                    for j in range(num_values):
                        try:
                            val_name, _, _ = winreg.EnumValue(sid_key, j)
                            if self._pattern.search(val_name):
                                entry = f"BAM EXECUTION: {val_name}"
                                if entry not in existing:
                                    existing.add(entry)
                                    self._append_trace(entry)
                        except OSError:
                            continue
                    winreg.CloseKey(sid_key)
                except OSError:
                    continue
            winreg.CloseKey(bam_root)
        except Exception as e:
            logger.debug("_check_bam failed: %s", e)

    def _check_boot_config(self) -> None:
        try:
            output = subprocess.check_output(
                ["bcdedit", "/enum", "all"],
                text=True,
                errors="ignore",
                timeout=15,
            )
            m = self._pattern.search(output)
            if m:
                self._append_trace(f"BOOT CONFIG: Boot entry related to {m.group()}")
        except Exception as e:
            logger.debug("_check_boot_config failed: %s", e)

    def _check_netstat(self) -> None:
        try:
            output = subprocess.check_output(
                ["netstat", "-anob"], text=True, errors="ignore", timeout=30
            )
            m = self._pattern.search(output)
            if m:
                self._append_trace(f"NETWORK: Active connection or listener for {m.group()}")
        except Exception as e:
            logger.debug("_check_netstat failed: %s", e)

    def _check_driverquery(self) -> None:
        try:
            output = subprocess.check_output(
                ["driverquery", "/v", "/fo", "csv"], text=True, errors="ignore", timeout=30
            )
            rows = list(csv.reader(output.splitlines()))
            if len(rows) <= 1:
                return

            existing = {item["text"] for item in self.found if isinstance(item, dict)}
            for row in rows[1:]:
                line = ",".join(row)
                m = self._pattern.search(line)
                if m:
                    d_name = row[0].strip() if row else m.group()
                    d_path = row[12].strip() if len(row) > 12 else ""
                    entry = f"DRIVERQUERY: Active loaded driver matching {m.group()} - {d_name}"
                    if d_path:
                        entry += f" | {d_path}"
                    if entry not in existing:
                        existing.add(entry)
                        self._append_trace(entry, active=True)
        except Exception as e:
            logger.debug("_check_driverquery failed: %s", e)
