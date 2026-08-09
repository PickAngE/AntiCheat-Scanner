import logging
import os
import re
import csv
from typing import List, Optional

from config.signatures import AntiCheatInfo
from config.sig_index import SignatureIndex

from .base import BaseChecker
from .detection import CATEGORY_TRACE, Detection
from .matchers import target_matches
from utils.attribution import resolve_ac_name
from utils.subprocess_helper import run_cmd

logger = logging.getLogger(__name__)


class TraceChecker(BaseChecker):
    CATEGORY = CATEGORY_TRACE

    def __init__(
        self,
        ac_database: List[AntiCheatInfo],
        sig_index: Optional[SignatureIndex] = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self._target_names: List[str] = []
        for ac in ac_database:
            self._target_names.extend(ac.services + ac.processes + ac.drivers)
        self._pattern: re.Pattern[str] = re.compile(r"(?!)")

    def _get_combined_pattern(self) -> re.Pattern[str]:
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
        ac_name = resolve_ac_name(text, self.ac_database, self.sig_index)
        self.append_detection(Detection(
            category=CATEGORY_TRACE, text=text, ac_name=ac_name, active=active,
        ))

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
        output = run_cmd(["ipconfig", "/displaydns"], timeout=15)
        if not output:
            return
        m = self._pattern.search(output.lower())
        if m:
            self._append_trace(f"DNS CACHE: Trace related to {m.group()}")

    def _check_env_vars(self) -> None:
        try:
            for key, value in os.environ.items():
                combined = f"{key} {value}"
                if self._pattern.search(combined):
                    self._append_trace(f"ENV VAR: {key}={value}")
        except Exception as e:
            logger.debug("_check_env_vars failed: %s", e)

    def _check_wmi_drivers(self) -> None:
        output = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_SystemDriver | "
                "Select-Object Name,DisplayName | Format-Table -AutoSize -HideTableHeaders",
            ],
            timeout=60,
        )
        if not output:
            return
        for line in output.splitlines():
            stripped = line.strip()
            if stripped and target_matches(stripped, self._target_names):
                self._append_trace(f"WMI DRIVER TRACE: {stripped}")

    def _check_named_pipes(self) -> None:
        try:
            for pipe_name in os.listdir(r"\\.\pipe"):
                if self._pattern.search(pipe_name):
                    self._append_trace(f"NAMED PIPE: \\\\.\\pipe\\{pipe_name}")
        except Exception as e:
            logger.debug("_check_named_pipes failed: %s", e)

    def _check_filter_drivers(self) -> None:
        output = run_cmd(["fltmc", "instances"], timeout=15)
        if not output:
            return
        for line in output.splitlines():
            stripped = line.strip()
            if stripped and self._pattern.search(stripped):
                self._append_trace(f"FILTER DRIVER: {stripped}", active=True)

    def _check_event_logs(self) -> None:
        output = run_cmd(
            [
                "wevtutil",
                "qe",
                "System",
                "/q:*[System[Provider[@Name='Service Control Manager']]]",
                "/f:text",
                "/c:300",
                "/rd:true",
            ],
            timeout=60,
        )
        if not output:
            return
        m = self._pattern.search(output)
        if m:
            self._append_trace(f"EVENT LOG: System log contains trace of {m.group()}")

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
                            if self._pattern.search(val_name):
                                self._append_trace(f"DEFENDER EXCLUSION: {val_name}")
                        except OSError:
                            continue
                    winreg.CloseKey(handle)
                except (FileNotFoundError, OSError):
                    continue
        except Exception as e:
            logger.debug("_check_defender_exclusions failed: %s", e)

    def _check_firewall_rules(self) -> None:
        output = run_cmd(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
            timeout=60,
        )
        if not output:
            return
        m = self._pattern.search(output)
        if m:
            self._append_trace(f"FIREWALL RULE: Inbound rule related to {m.group()}")

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
                            if self._pattern.search(val_name):
                                self._append_trace(f"BAM EXECUTION: {val_name}")
                        except OSError:
                            continue
                    winreg.CloseKey(sid_key)
                except OSError:
                    continue
            winreg.CloseKey(bam_root)
        except Exception as e:
            logger.debug("_check_bam failed: %s", e)

    def _check_boot_config(self) -> None:
        output = run_cmd(["bcdedit", "/enum", "all"], timeout=15)
        if not output:
            return
        m = self._pattern.search(output)
        if m:
            self._append_trace(f"BOOT CONFIG: Boot entry related to {m.group()}")

    def _check_netstat(self) -> None:
        output = run_cmd(["netstat", "-anob"], timeout=60)
        if not output:
            return
        for line in output.splitlines():
            bracket_match = re.search(r"\[([^\]]+)\]", line)
            if not bracket_match:
                continue
            process_name = bracket_match.group(1)
            m = self._pattern.search(process_name)
            if m:
                self._append_trace(
                    f"NETWORK: Active connection or listener for {m.group()} ({process_name})"
                )

    def _check_driverquery(self) -> None:
        output = run_cmd(["driverquery", "/v", "/fo", "csv"], timeout=60)
        if not output:
            return
        try:
            reader = csv.DictReader(output.splitlines())
            fieldnames = reader.fieldnames or []
            path_col = None
            for col in ("Path", "Chemin"):
                if col in fieldnames:
                    path_col = col
                    break
            if not path_col and fieldnames:
                logger.debug(
                    "driverquery: unknown header %s, falling back to index 12",
                    fieldnames,
                )

            for row in reader:
                if not row:
                    continue
                line = ",".join(row.values())
                m = self._pattern.search(line)
                if not m:
                    continue
                d_name = next(iter(row.values()), m.group()).strip()
                if path_col:
                    d_path = row.get(path_col, "").strip()
                else:
                    values = list(row.values())
                    d_path = values[12].strip() if len(values) > 12 else ""
                entry = f"DRIVERQUERY: Active loaded driver matching {m.group()} - {d_name}"
                if d_path:
                    entry += f" | {d_path}"
                self._append_trace(entry, active=True)
        except Exception as e:
            logger.debug("_check_driverquery parse failed: %s", e)
