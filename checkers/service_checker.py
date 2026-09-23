from __future__ import annotations

import logging
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
                found_match = target_matches(service_name, self._all_signatures) or target_matches(
                    display_name,
                    self._all_signatures,
                )
                executable = ""
                if not found_match:
                    raw_binpath = service.binpath() or ""
                    if raw_binpath:
                        executable = extract_exe_path(raw_binpath)
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
            except (OSError, TypeError, ValueError) as exc:
                self.fail_count += 1
                logger.debug("ServiceChecker could not inspect a service: %s", format_error(exc))
