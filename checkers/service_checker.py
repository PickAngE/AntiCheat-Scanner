import logging
from typing import List

import psutil

from .base import BaseChecker
from .matchers import content_matches, extract_exe_path, target_matches
from utils.attribution import resolve_ac_name

logger = logging.getLogger(__name__)


class ServiceChecker(BaseChecker):
    def __init__(self, ac_database, sig_index=None) -> None:
        super().__init__(ac_database, sig_index)
        self._all_sigs: List[str] = []
        for ac in ac_database:
            self._all_sigs.extend(ac.services + ac.processes + ac.drivers)

    def check(self) -> None:
        try:
            for service in psutil.win_service_iter():
                try:
                    svc_name = service.name()
                    svc_display = service.display_name()
                    raw_binpath = ""
                    exe_path = ""

                    found_match = target_matches(svc_name, self._all_sigs) or target_matches(
                        svc_display, self._all_sigs
                    )
                    if not found_match:
                        try:
                            raw_binpath = service.binpath() or ""
                            if raw_binpath:
                                exe_path = extract_exe_path(raw_binpath)
                                found_match = content_matches(
                                    exe_path, self._all_sigs, min_length=4
                                ) or target_matches(exe_path, self._all_sigs)
                        except Exception as e:
                            logger.debug("Service binpath check failed: %s", e)

                    if not found_match:
                        continue

                    svc_dict = service.as_dict()
                    ac_name = resolve_ac_name(
                        svc_name,
                        self.ac_database,
                        self.sig_index,
                    ) or resolve_ac_name(
                        svc_display,
                        self.ac_database,
                        self.sig_index,
                    ) or (
                        resolve_ac_name(exe_path, self.ac_database, self.sig_index)
                        if exe_path
                        else None
                    )
                    if ac_name:
                        svc_dict["ac_name"] = ac_name
                    self.found.append(svc_dict)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug("ServiceChecker failed: %s", e)
