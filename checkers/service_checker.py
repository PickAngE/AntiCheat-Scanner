from __future__ import annotations

import logging
import re
from typing import Any, ClassVar

import psutil

from checkers.base import BaseChecker
from checkers.detection import CATEGORY_SVC, Detection
from checkers.matchers import content_matches, extract_exe_path, target_matches
from config.sig_index import SignatureIndex
from config.signatures import AntiCheatInfo
from utils.attribution import resolve_ac_name
from utils.subprocess_helper import format_error

logger = logging.getLogger(__name__)

_WORD_TOKENS = re.compile(r"[^a-z0-9]+")


class ServiceChecker(BaseChecker):
    CATEGORY: ClassVar[str] = CATEGORY_SVC

    def __init__(
        self,
        ac_database: list[AntiCheatInfo],
        sig_index: SignatureIndex | None = None,
    ) -> None:
        super().__init__(ac_database, sig_index)




        self._all_signatures = [
            signature for ac in ac_database for signature in ac.services + ac.processes + ac.drivers
        ]


        self._target_exact = {
            base
            for signature in self._all_signatures
            for base in (signature.casefold().strip(),)
            if len(base) >= 3
        }

        self._target_substr = {base for base in self._target_exact if len(base) >= 5}

    def _might_match(self, *texts: str) -> bool:
        if self.sig_index is not None and any(
            text and self.sig_index.lookup(text) for text in texts
        ):
            return True
        combined = " ".join(texts).casefold()
        tokens = {token for token in _WORD_TOKENS.split(combined) if token}
        if tokens & self._target_exact:
            return True
        return any(base in combined for base in self._target_substr)

    def check(self) -> None:
        try:
            services = psutil.win_service_iter()
        except (OSError, psutil.Error) as exc:
            self.fail_count += 1
            logger.error("Service enumeration failed: %s", format_error(exc))
            return
        for service in services:
            try:
                service_name = service.name()
                display_name = service.display_name()
                try:
                    raw_binpath = service.binpath() or ""
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    raw_binpath = ""
                executable = extract_exe_path(raw_binpath) if raw_binpath else ""
                if not self._might_match(service_name, display_name, executable):
                    continue
                found_match = target_matches(service_name, self._all_signatures) or target_matches(
                    display_name,
                    self._all_signatures,
                )
                if not found_match and executable:
                    found_match = content_matches(
                        executable,
                        self._all_signatures,
                    ) or target_matches(executable, self._all_signatures)
                if not found_match:
                    continue

                service_data: dict[str, Any] = service.as_dict()
                status = str(service_data.get("status", ""))
                active = status.casefold() == "running"
                label = display_name or service_name
                ac_name = (
                    resolve_ac_name(
                        service_name,
                        self.ac_database,
                        self.sig_index,
                    )
                    or resolve_ac_name(
                        display_name,
                        self.ac_database,
                        self.sig_index,
                    )
                    or (
                        resolve_ac_name(executable, self.ac_database, self.sig_index)
                        if executable
                        else None
                    )
                )
                self.append_detection(
                    Detection(
                        category=CATEGORY_SVC,
                        text=f"{label} {'[RUNNING]' if active else '[STOPPED]'}",
                        ac_name=ac_name,
                        active=active,
                        raw=service_data,
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except (OSError, psutil.Error, TypeError, ValueError) as exc:
                self.fail_count += 1
                logger.debug("ServiceChecker could not inspect a service: %s", format_error(exc))
