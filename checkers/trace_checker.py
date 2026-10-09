from __future__ import annotations

import csv
import logging
import os
import re
from collections.abc import Sequence
from typing import ClassVar

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_TRACE, Detection
from checkers.matchers import strip_binary_suffix, target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_name
from utils.subprocess_helper import CommandResult, format_error, run_cmd, system_tool

logger = logging.getLogger(__name__)


_PATH_COLUMN_HINTS = ("path", "chemin", "pfad", "percorso", "pad", "ruta", "caminho")


_STATE_COLUMN_HINTS = (
    "state",
    "état",
    "etat",
    "zustand",
    "estado",
    "stato",
    "toestand",
    "tilstand",
    "tillstånd",
    "tillstand",
    "tila",
    "stare",
    "durum",
    "stan",
    "állapot",
    "allapot",
    "κατάσταση",
)




_RUNNING_STATE_STEMS = (
    "running",
    "started",
    "démarr",
    "en cours",
    "gestartet",
    "ausgeführt",
    "ausgefuehrt",
    "läuft",
    "lauft",
    "ejecuci",
    "esecuzione",
    "avviat",
    "execu",
    "werkt",
    "kører",
    "korer",
    "kör",
    "käynnissä",
    "kaynnissa",
    "uruchom",
    "запущ",
    "працює",
    "prats",
    "funger",
    "calis",
    "λειτουργ",
)

_MAX_SNIPPET_LENGTH = 200


def _snippet(text: str, limit: int = _MAX_SNIPPET_LENGTH) -> str:
    cleaned = " ".join(str(text or "").strip().split())
    if len(cleaned) > limit:
        return cleaned[:limit] + "..."
    return cleaned


def _sniff_csv_delimiter(header_line: str) -> str:
    if ";" in header_line and header_line.count(";") >= header_line.count(","):
        return ";"
    return ","


def _is_running_state(cell: str) -> bool:
    lowered = cell.strip().lower()
    return any(stem in lowered for stem in _RUNNING_STATE_STEMS)


def _resolve_state_column(fieldnames: Sequence[str]) -> str | None:
    lowered = {column.lower(): column for column in fieldnames}
    for hint in _STATE_COLUMN_HINTS:
        for lower_name, original in lowered.items():
            if hint in lower_name:
                return original
    return None


class TraceChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_TRACE

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
        eventlog_limit: int = 300,
    ) -> None:
        super().__init__(ac_database, sig_index)
        if eventlog_limit < 1:
            raise ValueError("eventlog_limit must be greater than zero")
        self.eventlog_limit = eventlog_limit
        self._target_names = [
            name for ac in ac_database for name in ac.services + ac.processes + ac.drivers
        ]



        self._pattern = re.compile(r"(?!)")

    def _clean_target(self, target: str) -> str:
        return strip_binary_suffix(target).casefold().strip()

    def _get_combined_pattern(self) -> re.Pattern[str]:
        clean_targets = list(
            dict.fromkeys(self._clean_target(target) for target in self._target_names)
        )
        clean_targets = [target for target in clean_targets if len(target) >= 3]
        if clean_targets:
            alternatives = "|".join(re.escape(target) for target in clean_targets)
            pattern = re.compile(
                rf"(?<![a-z0-9])(?:{alternatives})(?![a-z0-9])",
                re.IGNORECASE,
            )
        else:
            pattern = re.compile(r"(?!)")
        self._pattern = pattern
        return pattern

    def _matching_names(self, text: str, pattern: re.Pattern[str] | None = None) -> list[str]:
        active_pattern = pattern if pattern is not None else self._pattern
        return list(dict.fromkeys(match.group(0) for match in active_pattern.finditer(text)))

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
                ac_name=resolve_ac_name(
                    text,
                    self.ac_database,
                    self.sig_index,
                    include_products=True,
                    include_name=True,
                ),
                active=active,
            )
        )

    def check(self) -> None:
        pattern = self._get_combined_pattern()
        self._check_dns_cache(pattern)
        self._check_environment(pattern)
        self._check_wmi_drivers()
        self._check_named_pipes(pattern)
        self._check_filter_drivers(pattern)
        self._check_event_logs(pattern)
        self._check_defender_exclusions(pattern)
        self._check_firewall_rules(pattern)
        self._check_bam(pattern)
        self._check_boot_config(pattern)
        self._check_netstat(pattern)
        self._check_driverquery(pattern)

    def _check_dns_cache(self, pattern: re.Pattern[str] | None = None) -> None:
        output = self._run([system_tool("ipconfig.exe"), "/displaydns"], timeout=15)
        if not output:
            return
        for line in output.splitlines():
            for name in self._matching_names(line, pattern):
                self._append_trace(f"DNS CACHE: {name} in {_snippet(line, 120)}")

    def _check_environment(self, pattern: re.Pattern[str] | None = None) -> None:
        try:
            for key, value in os.environ.items():
                combined = f"{key} {value}"
                names = self._matching_names(combined, pattern)
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
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-CimInstance Win32_SystemDriver | "
                "Select-Object Name,DisplayName,State,Started,PathName | "
                "ConvertTo-Csv -NoTypeInformation",
            ],
            timeout=60,
        )
        if not output:
            return
        if self._parse_wmi_csv(output):
            return

        for line in output.splitlines():
            stripped = line.strip()
            if stripped and target_matches(stripped, self._target_names):
                self._append_trace(f"WMI DRIVER TRACE: {stripped}")

    def _parse_wmi_csv(self, output: str) -> bool:
        lines = [line for line in output.splitlines() if line.strip()]
        if len(lines) < 2 or ("," not in lines[0] and ";" not in lines[0]):
            return False
        try:
            reader = csv.DictReader(lines, delimiter=_sniff_csv_delimiter(lines[0]))
            fieldnames = reader.fieldnames or []
            if not {"Name", "DisplayName", "State"}.intersection(set(fieldnames)):
                return False
            parsed_any = False
            for row in reader:
                parsed_any = True
                name = str(row.get("Name") or "").strip()
                display = str(row.get("DisplayName") or "").strip()
                state = str(row.get("State") or "")
                started = str(row.get("Started") or "")
                pathname = str(row.get("PathName") or "")
                combined = " ".join(part for part in (name, display, pathname) if part)
                if combined and target_matches(combined, self._target_names):
                    active = _is_running_state(state) or started.strip().lower() in {
                        "true",
                        "1",
                    }
                    label = name or display or pathname
                    self._append_trace(f"WMI DRIVER TRACE: {label}", active=active)
            return parsed_any
        except (OSError, csv.Error) as exc:
            logger.debug("WMI CSV parse failed: %s", format_error(exc))
            return False

    def _check_named_pipes(self, pattern: re.Pattern[str] | None = None) -> None:
        try:
            for pipe_name in os.listdir(r"\\.\pipe"):
                if self._matching_names(pipe_name, pattern):
                    self._append_trace(f"NAMED PIPE: \\\\.\\pipe\\{pipe_name}")
        except OSError as exc:
            self.fail_count += 1
            logger.debug("Named pipe scan failed: %s", format_error(exc))

    def _check_filter_drivers(self, pattern: re.Pattern[str] | None = None) -> None:

        output = self._run([system_tool("fltmc.exe"), "instances"], timeout=15)
        for line in (output or "").splitlines():
            stripped = line.strip()
            if stripped and self._matching_names(stripped, pattern):
                self._append_trace(f"FILTER DRIVER: {stripped}", active=True)

    def _check_event_logs(self, pattern: re.Pattern[str] | None = None) -> None:
        output = self._run(
            [
                system_tool("wevtutil.exe"),
                "qe",
                "System",
                "/q:*[System[Provider[@Name='Service Control Manager']]]",
                "/f:text",
                f"/c:{self.eventlog_limit}",
                "/rd:true",
            ],
            timeout=60,
        )
        if not output:
            return
        for line in output.splitlines():
            for name in self._matching_names(line, pattern):
                self._append_trace(f"EVENT LOG: {name} in {_snippet(line)}")

    def _check_defender_exclusions(self, pattern: re.Pattern[str] | None = None) -> None:
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
                            if self._matching_names(str(value_name or ""), pattern):
                                self._append_trace(
                                    f"DEFENDER EXCLUSION: {_snippet(str(value_name))}"
                                )
                            if isinstance(value_data, str) and self._matching_names(
                                value_data, pattern
                            ):
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

    def _check_firewall_rules(self, pattern: re.Pattern[str] | None = None) -> None:
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
        if not output:
            return
        for line in output.splitlines():
            for name in self._matching_names(line, pattern):
                self._append_trace(f"FIREWALL RULE: {name} in {_snippet(line)}")

    def _check_bam(self, pattern: re.Pattern[str] | None = None) -> None:
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
                                if self._matching_names(str(value_name or ""), pattern):
                                    self._append_trace(
                                        f"BAM EXECUTION: {_snippet(str(value_name))}"
                                    )
                finally:
                    winreg.CloseKey(root)

        except (ImportError, OSError) as exc:
            self.fail_count += 1
            logger.debug("BAM scan failed: %s", format_error(exc))

    def _check_boot_config(self, pattern: re.Pattern[str] | None = None) -> None:
        output = self._run([system_tool("bcdedit.exe"), "/enum", "all"], timeout=15)
        if not output:
            return
        for line in output.splitlines():
            for name in self._matching_names(line, pattern):
                self._append_trace(f"BOOT CONFIG: {name} in {_snippet(line)}")

    def _check_netstat(self, pattern: re.Pattern[str] | None = None) -> None:





        output = self._run([system_tool("netstat.exe"), "-anob"], timeout=60)
        if not output:
            return
        block_active = False
        block_has_connection = False
        block_processes: list[str] = []

        def flush() -> None:
            if not block_has_connection:
                return
            for process_name in block_processes:
                for name in self._matching_names(process_name, pattern):
                    self._append_trace(
                        f"NETWORK: {name} ({process_name}) in {_snippet(process_name)}",
                        active=block_active,
                    )

        for line in [*output.splitlines(), ""]:
            stripped = line.strip()
            if not stripped:
                flush()
                block_active = False
                block_has_connection = False
                block_processes = []
                continue
            upper = stripped.upper()
            if upper.startswith(("TCP", "UDP")):
                flush()
                block_active = "ESTABLISHED" in upper or "LISTENING" in upper
                block_has_connection = True
                block_processes = []
                continue
            bracket_match = re.fullmatch(r"\[([^\]]+)\]", stripped)
            if bracket_match and block_has_connection:
                block_processes.append(bracket_match.group(1))
        flush()

    def _resolve_driverquery_path(self, row: dict[str, str], fieldnames: Sequence[str]) -> str:
        lowered = {column.lower(): column for column in fieldnames}
        for hint in _PATH_COLUMN_HINTS:
            for lower_name, original in lowered.items():
                if hint in lower_name:
                    return str(row.get(original, "") or "").strip()

        values = list(row.values())
        for value in reversed(values):
            text = str(value or "").strip()
            if ":\\" in text or "\\\\" in text:
                return text
        return ""

    def _driverquery_is_running(
        self, row: dict[str, str], fieldnames: Sequence[str], line: str
    ) -> bool:
        state_column = _resolve_state_column(fieldnames)
        if state_column is not None:
            return _is_running_state(str(row.get(state_column) or ""))
        return _is_running_state(line)

    def _check_driverquery(self, pattern: re.Pattern[str] | None = None) -> None:
        output = self._run(
            [system_tool("driverquery.exe"), "/v", "/fo", "csv"],
            timeout=60,
        )
        if not output:
            return
        try:
            lines = output.splitlines()
            reader = csv.DictReader(lines, delimiter=_sniff_csv_delimiter(lines[0] if lines else ""))
            fieldnames = reader.fieldnames or []
            for row in reader:
                line = ",".join(str(value) for value in row.values())
                names = self._matching_names(line, pattern)
                if not names:
                    continue
                driver_name = next(iter(row.values()), names[0]).strip()
                driver_path = self._resolve_driverquery_path(row, fieldnames)
                entry = f"DRIVERQUERY: {names[0]} - {driver_name} in {_snippet(line, 120)}"
                if driver_path:
                    entry += f" | {driver_path}"
                self._append_trace(
                    entry,
                    active=self._driverquery_is_running(row, fieldnames, line),
                )
        except (OSError, csv.Error) as exc:
            self.fail_count += 1
            logger.debug("Driverquery parse failed: %s", format_error(exc))
