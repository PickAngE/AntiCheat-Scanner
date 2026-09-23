from __future__ import annotations

import csv
import logging
import os
import re
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_TRACE, Detection
from checkers.matchers import target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_name
from utils.subprocess_helper import CommandResult, format_error, run_cmd, system_tool

logger = logging.getLogger(__name__)


class TraceChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_TRACE

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)
        self._target_names = [
            name for ac in ac_database for name in ac.services + ac.processes + ac.drivers
        ]
        self._pattern = re.compile(r"(?!)")

    def _clean_target(self, target: str) -> str:
        normalized = target.casefold().strip()
        for extension in (".exe", ".sys", ".dll"):
            if normalized.endswith(extension):
                return normalized[: -len(extension)]
        return normalized

    def _get_combined_pattern(self) -> re.Pattern[str]:
        clean_targets = list(
            dict.fromkeys(self._clean_target(target) for target in self._target_names)
        )
        clean_targets = [target for target in clean_targets if len(target) >= 3]
        if clean_targets:
            alternatives = "|".join(re.escape(target) for target in clean_targets)
            self._pattern = re.compile(
                rf"(?<![a-z0-9])(?:{alternatives})(?![a-z0-9])",
                re.IGNORECASE,
            )
        else:
            self._pattern = re.compile(r"(?!)")
        return self._pattern

    def _matching_names(self, text: str) -> list[str]:
        return list(dict.fromkeys(match.group(0) for match in self._pattern.finditer(text)))

    def _run(self, arguments: list[str], timeout: int) -> str:
        result = run_cmd(arguments, timeout=timeout)
        if isinstance(result, CommandResult):
            if not result.available:
                self.fail_count += 1
            return result.output
        return str(result or "")

    def _append_trace(self, text: str, active: bool = False) -> None:
        self.append_detection(
            Detection(
                category=CATEGORY_TRACE,
                text=text,
                ac_name=resolve_ac_name(text, self.ac_database, self.sig_index),
                active=active,
            )
        )

    def check(self) -> None:
        self._get_combined_pattern()
        self._check_dns_cache()
        self._check_environment()
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
        output = self._run([system_tool("ipconfig.exe"), "/displaydns"], timeout=15)
        for name in self._matching_names(output or ""):
            self._append_trace(f"DNS CACHE: Trace related to {name}")

    def _check_environment(self) -> None:
        try:
            for key, value in os.environ.items():
                combined = f"{key} {value}"
                names = self._matching_names(combined)
                if names:
                    self._append_trace(f"ENV VAR: {key} (matches {', '.join(names)})")
        except OSError as exc:
            self.fail_count += 1
            logger.debug("Environment trace scan failed: %s", format_error(exc))

    def _check_wmi_drivers(self) -> None:
        output = self._run(
            [
                system_tool("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName | Format-Table -AutoSize -HideTableHeaders",
            ],
            timeout=60,
        )
        for line in (output or "").splitlines():
            stripped = line.strip()
            if stripped and target_matches(stripped, self._target_names):
                self._append_trace(f"WMI DRIVER TRACE: {stripped}")

    def _check_named_pipes(self) -> None:
        try:
            for pipe_name in os.listdir(r"\\.\pipe"):
                if self._matching_names(pipe_name):
                    self._append_trace(f"NAMED PIPE: \\\\.\\pipe\\{pipe_name}")
        except OSError as exc:
            self.fail_count += 1
            logger.debug("Named pipe scan failed: %s", format_error(exc))

    def _check_filter_drivers(self) -> None:
        output = self._run([system_tool("fltmc.exe"), "instances"], timeout=15)
        for line in (output or "").splitlines():
            stripped = line.strip()
            if stripped and self._matching_names(stripped):
                self._append_trace(f"FILTER DRIVER: {stripped}", active=True)

    def _check_event_logs(self) -> None:
        output = self._run(
            [
                system_tool("wevtutil.exe"),
                "qe",
                "System",
                "/q:*[System[Provider[@Name='Service Control Manager']]]",
                "/f:text",
                "/c:300",
                "/rd:true",
            ],
            timeout=60,
        )
        names = self._matching_names(output or "")
        for name in names:
            self._append_trace(f"EVENT LOG: System log contains trace of {name}")

    def _check_defender_exclusions(self) -> None:
        try:
            import winreg

            paths = (
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
                ),
            )
            for hive, subkey in paths:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as handle:
                        for index in range(winreg.QueryInfoKey(handle)[1]):
                            value_name, value_data, _ = winreg.EnumValue(handle, index)
                            if self._matching_names(value_name):
                                self._append_trace(f"DEFENDER EXCLUSION: {value_name}")
                            if isinstance(value_data, str) and self._matching_names(value_data):
                                self._append_trace(
                                    f"DEFENDER EXCLUSION VALUE: {value_name}=<redacted>"
                                )
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    self.fail_count += 1
                    logger.debug(
                        "Defender exclusion scan failed for %s: %s", subkey, format_error(exc)
                    )
        except (ImportError, OSError) as exc:
            self.fail_count += 1
            logger.debug("Defender registry scan failed: %s", format_error(exc))

    def _check_firewall_rules(self) -> None:
        output = self._run(
            [
                system_tool("netsh.exe"),
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=all",
                "dir=in",
            ],
            timeout=60,
        )
        for name in self._matching_names(output or ""):
            self._append_trace(f"FIREWALL RULE: Inbound rule related to {name}")

    def _check_bam(self) -> None:
        try:
            import winreg

            paths = (
                r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            )
            for path in paths:
                try:
                    root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                except FileNotFoundError:
                    continue
                try:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        sid = winreg.EnumKey(root, index)
                        with winreg.OpenKey(root, sid) as sid_key:
                            for value_index in range(winreg.QueryInfoKey(sid_key)[1]):
                                value_name, _, _ = winreg.EnumValue(sid_key, value_index)
                                if self._matching_names(value_name):
                                    self._append_trace(f"BAM EXECUTION: {value_name}")
                finally:
                    winreg.CloseKey(root)
                break
        except (ImportError, OSError) as exc:
            self.fail_count += 1
            logger.debug("BAM scan failed: %s", format_error(exc))

    def _check_boot_config(self) -> None:
        output = self._run([system_tool("bcdedit.exe"), "/enum", "all"], timeout=15)
        for name in self._matching_names(output or ""):
            self._append_trace(f"BOOT CONFIG: Boot entry related to {name}")

    def _check_netstat(self) -> None:
        output = self._run([system_tool("netstat.exe"), "-anob"], timeout=60)
        for line in (output or "").splitlines():
            bracket_match = re.search(r"\[([^\]]+)\]", line)
            if not bracket_match:
                continue
            process_name = bracket_match.group(1)
            for name in self._matching_names(process_name):
                self._append_trace(f"NETWORK: Connection or listener for {name} ({process_name})")

    def _check_driverquery(self) -> None:
        output = self._run(
            [system_tool("driverquery.exe"), "/v", "/fo", "csv"],
            timeout=60,
        )
        if not output:
            return
        try:
            reader = csv.DictReader(output.splitlines())
            fieldnames = reader.fieldnames or []
            path_column = next(
                (column for column in ("Path", "Chemin") if column in fieldnames), None
            )
            for row in reader:
                line = ",".join(str(value) for value in row.values())
                names = self._matching_names(line)
                if not names:
                    continue
                driver_name = next(iter(row.values()), names[0]).strip()
                driver_path = ""
                if path_column:
                    driver_path = str(row.get(path_column, "")).strip()
                else:
                    values = list(row.values())
                    driver_path = str(values[12]).strip() if len(values) > 12 else ""
                entry = f"DRIVERQUERY: Loaded driver matching {names[0]} - {driver_name}"
                if driver_path:
                    entry += f" | {driver_path}"
                self._append_trace(entry, active=True)
        except (OSError, csv.Error) as exc:
            self.fail_count += 1
            logger.debug("Driverquery parse failed: %s", format_error(exc))
